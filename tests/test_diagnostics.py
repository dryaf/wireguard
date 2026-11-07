"""Catch upgrade/reboot failures without connecting to a VPS or changing rules."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "files"))
import wireguard_diagnostics as diagnostics


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        config = self.root / "etc/wireguard/wg0.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            "[Interface]\nAddress = 10.99.0.1/24\nMTU = 1280\nListenPort = 51820\n"
            "PrivateKey = DO_NOT_PRINT_PRIVATE_KEY\n"
            "PostUp = /usr/local/lib/wireguard-manager/wireguard_firewall.py up --dns 1.1.1.1 --wan ens3\n"
            "[Peer]\nPresharedKey = DO_NOT_PRINT_PRESHARED_KEY\n"
            "PublicKey = DO_NOT_PRINT_PEER_KEY\nAllowedIPs = 10.99.0.2/32\n"
        )
        (self.root / "etc/sysctl.conf").write_text("net.ipv4.ip_forward = 1\n")
        self.overrides = {}
        self.commands = []

    def runner(self, argv):
        self.commands.append(argv)
        key = tuple(argv)
        if key in self.overrides:
            return self.overrides[key]
        if argv[:2] == ["systemctl", "is-active"]:
            return 0, "active", ""
        if argv[:2] == ["systemctl", "is-enabled"]:
            return 0, "enabled", ""
        if argv[:2] == ["sysctl", "-n"]:
            return 0, "1", ""
        if argv[:3] == ["ip", "-details", "-4"]:
            return 0, "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280\n    inet 10.99.0.1/24 scope global wg0", ""
        if argv[:4] == ["ip", "-j", "-4", "route"]:
            return 0, '[{"dev": "ens3", "src": "192.0.2.1"}]', ""
        if argv == ["wg", "show", "wg0", "listen-port"]:
            return 0, "51820", ""
        if argv == ["wg", "show", "wg0", "latest-handshakes"]:
            return 0, f"DO_NOT_PRINT_PEER_KEY\t{int(time.time())}", ""
        return 0, "", ""

    def check(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = diagnostics.Diagnostics(root=self.root, runner=self.runner).check()
        return code, output.getvalue()

    def test_healthy_managed_server_omits_keys_and_checks_both_dns_transports(self):
        code, report = self.check()
        self.assertEqual(code, 0, report)
        self.assertIn("[PASS] IPv4 forwarding: 1", report)
        self.assertIn("[PASS] Internet masquerade rule", report)
        self.assertIn("[PASS] DNS redirect (udp)", report)
        self.assertIn("[PASS] DNS redirect (tcp)", report)
        self.assertIn("1/1 peers", report)
        self.assertNotIn("DO_NOT_PRINT", report)
        self.assertNotIn("dump", [value for command in self.commands for value in command])
        self.assertFalse(any(value in {"-A", "-D", "-I", "-F", "--flush", "restart", "start", "enable", "-w="}
                             for command in self.commands for value in command))

    def test_interface_forwarding_can_be_disabled_while_global_forwarding_is_enabled(self):
        self.overrides[("sysctl", "-n", "net.ipv4.conf.wg0.forwarding")] = (0, "0", "")
        self.overrides[("sysctl", "-n", "net/ipv4/conf/ens3/forwarding")] = (0, "0", "")
        code, report = self.check()
        self.assertEqual(code, 1)
        self.assertIn("[PASS] IPv4 forwarding: 1", report)
        self.assertIn("[FAIL] wg0 IPv4 forwarding: 0", report)
        self.assertIn("[FAIL] WAN IPv4 forwarding: 0", report)

    def test_reset_forwarding_missing_nat_and_stopped_service_are_all_reported(self):
        self.overrides[("sysctl", "-n", "net.ipv4.ip_forward")] = (0, "0", "")
        self.overrides[("systemctl", "is-active", "wg-quick@wg0")] = (3, "failed", "")
        original = self.runner

        def missing_nat(argv):
            if "-C" in argv and "POSTROUTING" in argv:
                return 1, "", ""
            return original(argv)

        self.runner = missing_nat
        code, report = self.check()
        self.assertEqual(code, 1)
        for name in ("WireGuard service", "IPv4 forwarding", "Internet masquerade rule"):
            self.assertIn(f"[FAIL] {name}", report)
        self.assertIn("Client handshakes", report)
        self.assertIn("Result: 3 failed check(s)", report)

    def test_changed_wan_is_a_failure_even_if_old_hook_rules_exist(self):
        self.overrides[("ip", "-j", "-4", "route", "get", "1.1.1.1")] = (0, '[{"dev":"ens4"}]', "")
        original = self.runner

        def old_nat_only(argv):
            if "-C" in argv and "POSTROUTING" in argv and argv[argv.index("-o") + 1] != "ens3":
                self.commands.append(argv)
                return 1, "", ""
            return original(argv)

        self.runner = old_nat_only
        code, report = self.check()
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] Hook WAN interface: configured=ens3, current Internet route=ens4", report)
        self.assertIn("[FAIL] Internet masquerade rule: WAN ens4: Managed rule missing", report)
        self.assertNotIn("[PASS] Internet masquerade rule", report)

    def test_automatic_wan_hook_is_validated_against_the_current_route(self):
        config = self.root / "etc/wireguard/wg0.conf"
        config.write_text(config.read_text().replace("--wan ens3", "--wan auto"))
        code, report = self.check()
        self.assertEqual(code, 0, report)
        self.assertIn("[PASS] Hook WAN interface: automatic detection at start; current Internet route=ens3", report)
        self.assertIn("[PASS] Internet masquerade rule: WAN ens3", report)
        checks = [command for command in self.commands if "-C" in command and "POSTROUTING" in command]
        self.assertEqual(checks[0][checks[0].index("-o") + 1], "ens3")

    def test_missing_interface_and_config_do_not_stop_remaining_checks(self):
        (self.root / "etc/wireguard/wg0.conf").unlink()
        self.overrides[("ip", "-details", "-4", "address", "show", "dev", "wg0")] = (1, "", "Device missing")
        self.overrides[("wg", "show", "wg0", "listen-port")] = (1, "", "No such device")
        code, report = self.check()
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] wg0 configuration", report)
        self.assertIn("WireGuard module for running kernel", report)
        self.assertIn("filter/FORWARD rules and counters", report)
        self.assertIn("Client Internet test", report)

    def test_persistent_ufw_override_and_idle_peers_warn_without_failing(self):
        ufw = self.root / "etc/ufw/sysctl.conf"
        ufw.parent.mkdir(parents=True)
        ufw.write_text("# net/ipv4/ip_forward=0\nnet/ipv4/ip_forward=0 # override\n")
        self.overrides[("wg", "show", "wg0", "latest-handshakes")] = (0, "PEER\t0", "")
        code, report = self.check()
        self.assertEqual(code, 0, report)
        self.assertIn("[WARN] Persistent forwarding override: /etc/ufw/sysctl.conf:2", report)
        self.assertIn("[WARN] Client handshakes", report)

    def test_live_config_drift_is_a_failure(self):
        self.overrides[("ip", "-details", "-4", "address", "show", "dev", "wg0")] = (
            0, "3: wg0: <POINTOPOINT,NOARP> mtu 12800\n    inet 10.88.0.1/24 scope global wg0", "")
        self.overrides[("wg", "show", "wg0", "listen-port")] = (0, "51821", "")
        code, report = self.check()
        self.assertEqual(code, 1)
        for name in ("wg0 administrative state", "Configured VPN address", "Configured MTU", "Configured listen port"):
            self.assertIn(f"[FAIL] {name}", report)

    def test_dnsfilter_failure_is_reported_without_aborting(self):
        config = self.root / "etc/wireguard/wg0.conf"
        config.write_text(config.read_text().replace("--dns 1.1.1.1 --wan ens3", "--dns 10.99.0.1 --wan ens3 --dns-port 1053"))
        self.overrides[("systemctl", "is-active", "wireguard-dnsfilter")] = (3, "inactive", "")
        with patch.object(diagnostics.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = OSError("unreachable")
            code, report = self.check()
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] DNS filter service", report)
        self.assertIn("[FAIL] DNS filter local health", report)
        self.assertIn("Client handshakes", report)

    def test_missing_tools_and_timeouts_are_bounded_results(self):
        for error, expected in ((FileNotFoundError(), 127), (subprocess.TimeoutExpired("iptables", 12), 126)):
            with self.subTest(error=error), patch.object(diagnostics.subprocess, "run", side_effect=error) as command:
                rc, _, _ = diagnostics.run(["iptables", "--version"])
                self.assertEqual(rc, expected)
                self.assertEqual(command.call_args.kwargs["timeout"], 12)

    def test_hook_injection_is_rejected_without_printing_or_executing_config(self):
        config = self.root / "etc/wireguard/wg0.conf"
        config.write_text(config.read_text().replace("--wan ens3", "--wan ens3;touch /tmp/DO_NOT_PRINT"))
        code, report = self.check()
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] wg0 configuration", report)
        self.assertNotIn("DO_NOT_PRINT", report)
        self.assertFalse(any("touch" in part for command in self.commands for part in command))


class DiagnosticsPlaybookTests(unittest.TestCase):
    def test_report_is_printed_before_failure_and_checks_run_in_check_mode(self):
        for exit_code, check_mode in ((0, False), (1, False), (1, True)):
            with self.subTest(exit_code=exit_code, check_mode=check_mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = root / "probe.py"
                script.write_text(
                    "import sys\n"
                    "print('[INFO] FINAL_PROBE_DONE')\n"
                    + ("print('[FAIL] IPv4 forwarding: 0')\n" if exit_code else "")
                    + "print('Shared connection to 192.0.2.1 closed.', file=sys.stderr)\n"
                    + f"raise SystemExit({exit_code})\n"
                )
                plays = yaml.safe_load((ROOT / "server_debug_vpn.yml").read_text())
                plays[0].update(hosts="all", become=False, vars={
                    "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                })
                plays[0]["tasks"][0]["ansible.builtin.script"] = {
                    "cmd": str(script), "executable": sys.executable,
                }
                playbook = root / "probe.yml"
                playbook.write_text(yaml.safe_dump(plays))
                result = subprocess.run(["ansible-playbook", "-i", "fixture,", str(playbook),
                                         *(["--check"] if check_mode else [])],
                                        cwd=ROOT, text=True, capture_output=True,
                                        env=dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json"))
                self.assertEqual(result.returncode == 0, exit_code == 0, result.stdout + result.stderr)
                report = json.loads(result.stdout)
                tasks = report["plays"][0]["tasks"]
                self.assertIn("FINAL_PROBE_DONE", str(tasks[1]["hosts"]["fixture"]["msg"]))
                self.assertEqual(report["stats"]["fixture"]["changed"], 0)
                message = tasks[-1]["hosts"]["fixture"]["msg"]
                self.assertNotIn("Shared connection", message)
                if exit_code:
                    self.assertIn("[FAIL] IPv4 forwarding: 0", message)
                    self.assertIn("Next hints", message)

    def test_diagnostic_crash_includes_output_without_ssh_close_noise(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "crash.py"
            script.write_text(
                "import sys\n"
                "print('[INFO] Partial diagnostic output')\n"
                "print('Probe crashed: example error', file=sys.stderr)\n"
                "print('Shared connection to 192.0.2.1 closed.', file=sys.stderr)\n"
                "raise SystemExit(2)\n"
            )
            plays = yaml.safe_load((ROOT / "server_debug_vpn.yml").read_text())
            plays[0].update(hosts="all", become=False, vars={
                "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
            })
            plays[0]["tasks"][0]["ansible.builtin.script"] = {
                "cmd": str(script), "executable": sys.executable,
            }
            playbook = root / "probe.yml"
            playbook.write_text(yaml.safe_dump(plays))
            result = subprocess.run(["ansible-playbook", "-i", "fixture,", str(playbook)],
                                    cwd=ROOT, text=True, capture_output=True,
                                    env=dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json"))
            self.assertNotEqual(result.returncode, 0)
            message = json.loads(result.stdout)["plays"][0]["tasks"][-1]["hosts"]["fixture"]["msg"]
            self.assertIn("diagnostic exit code 2", message)
            self.assertIn("may have failed to start or stopped unexpectedly", message)
            self.assertIn("[INFO] Partial diagnostic output", message)
            self.assertIn("Probe crashed: example error", message)
            self.assertNotIn("Shared connection", message)


if __name__ == "__main__":
    unittest.main()

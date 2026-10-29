"""Real Netfilter and killed hook processes; service lifecycle is simulated here."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "files"), str(ROOT / "filter_plugins"), str(ROOT / "tests")]
from test_manager import FakeSystem
from wireguard_firewall import DNS_TAG, HELPER, OperationError, WireGuardFirewall, managed_policy, run_command
from wireguard_manager import WireGuardManager, atomic_write


def run_tests(environment):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        marker = directory / "inject"
        wrapper = directory / "iptables-restore"
        wrapper.write_text('''#!/usr/bin/python3
import os, pathlib, signal, subprocess, sys
data = sys.stdin.read()
marker = pathlib.Path(__file__).with_name('inject')
if marker.exists() and '--to-destination 2.2.2.2:53' in data:
    mode = marker.read_text()
    marker.unlink()
    if mode == 'kill':
        data = '\\n'.join(line for line in data.splitlines() if '-p tcp ' not in line) + '\\n'
        subprocess.run(['/usr/sbin/iptables-restore', *sys.argv[1:]], input=data, text=True, check=True)
        os.kill(os.getppid(), signal.SIGKILL)
        sys.exit(0)
    data = data.replace('-j DNAT', '-j NONEXISTENT_TARGET')
result = subprocess.run(['/usr/sbin/iptables-restore', *sys.argv[1:]], input=data, text=True)
sys.exit(result.returncode)
''')
        wrapper.chmod(0o700)
        firewall = WireGuardFirewall(directory)

        class Lifecycle(FakeSystem):
            def __call__(self, argv, stdin=None):
                if argv[0] in ("iptables-save", "iptables-restore"):
                    return run_command(argv, stdin)
                if argv == ["systemctl", "stop", "wg-quick@wg0"] and self.active:
                    firewall.down()
                result = super().__call__(argv, stdin)
                if argv[0] == "systemctl" and argv[1] in ("start", "restart", "enable"):
                    # Failed ExecStart does not run ExecStop. Use the real hook
                    # process, including SIGKILL before it can clean up its rules.
                    self.active = False
                    dns, wan = managed_policy((directory / "wg0.conf").read_text())
                    process = subprocess.run(
                        [sys.executable, HELPER, "--directory", str(directory), "up", "--dns", dns, "--wan", wan],
                        env=dict(os.environ, PATH=str(directory) + ":" + os.environ["PATH"]),
                        capture_output=True, text=True, timeout=30,
                    )
                    if process.returncode:
                        raise OperationError("Injected native PostUp failure")
                    self.active = True
                return result

        values = dict(wireguard_address="10.99.0.1/24", wireguard_port=51820, wireguard_mtu=1280,
                      server_priv_key_final="TEST_ONLY", ansible_facts={"default_ipv4": {"interface": "wan0"}}, dns_server="1.1.1.1")
        original = environment.get_template("wg0.conf.j2").render(**values).rstrip() + "\n"
        atomic_write(directory / "wg0.conf", original)
        stage = directory / "staged"
        stage.mkdir()
        candidate = stage / "wg0.conf"
        atomic_write(candidate, environment.get_template("wg0.conf.j2").render(**dict(values, dns_server="2.2.2.2")))
        manager = WireGuardManager(directory, Lifecycle(directory))
        run_command(["iptables", "-A", "FORWARD", "-i", "wan0", "-m", "comment", "--comment", "unrelated-release-rule", "-j", "ACCEPT"])
        before_check = {tool: run_command([tool]) for tool in ("iptables-save", "ip6tables-save")}
        assert firewall.check() is False
        # Exercise the installed script's system-Python shebang and imports.
        assert json.loads(run_command([HELPER, "check"])) == {"ok": True, "changed": False}
        for tool, before in before_check.items():
            # iptables-save has timestamp comments; compare only actual rules.
            meaningful = lambda text: [line for line in text.splitlines() if not line.startswith("#")]
            assert meaningful(run_command([tool])) == meaningful(before)
        print("PASS: firewall permission preflight leaves existing rules unchanged")
        assert firewall.up("1.1.1.1", "wan0") is True
        assert firewall.up("1.1.1.1", "wan0") is False
        previous = firewall.owned_rules()
        assert sum(len(lines) for lines in previous.values()) == 4
        for mode in ("error", "kill"):
            marker.write_text(mode)
            try:
                manager.apply(candidate)
            except OperationError as error:
                assert "previous configuration was restored" in str(error), str(error)
            else:
                raise AssertionError("Failed PostUp was reported as successful")
            assert not marker.exists(), "Failure injection was not exercised"
            assert (directory / "wg0.conf").read_text() == original
            assert firewall.owned_rules() == previous
            assert "2.2.2.2:53" not in run_command(["iptables-save", "-t", "nat"])
            assert "unrelated-release-rule" in run_command(["iptables-save", "-t", "filter"])
            print(f"PASS: real Netfilter rollback after hook {mode} (simulated service lifecycle)")
        assert firewall.down() is True
        assert firewall.down() is False
        assert "unrelated-release-rule" in run_command(["iptables-save", "-t", "filter"])
        run_command(["iptables", "-D", "FORWARD", "-i", "wan0", "-m", "comment", "--comment", "unrelated-release-rule", "-j", "ACCEPT"])
        print("PASS: real Netfilter idempotence and unrelated-rule preservation")

        run_command(["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "1053", "-j", "ACCEPT"])
        assert firewall.up("10.99.0.1", "wan0", 1053)
        assert firewall.protect_dns() is False
        for executable in ("iptables-save", "ip6tables-save"):
            inputs = [line for line in run_command([executable, "-t", "filter"]).splitlines() if line.startswith("-A INPUT ")]
            assert all(DNS_TAG in line for line in inputs[:6])
            assert inputs[2].endswith("-j DROP") and inputs[5].endswith("-j DROP")
        redirects = run_command(["iptables-save", "-t", "nat"])
        for protocol in ("udp", "tcp"):
            assert any(f"-p {protocol}" in line and "--dport 53" in line and "--to-destination 10.99.0.1:1053" in line for line in redirects.splitlines())
        firewall.down()
        assert len(firewall.owned_rules(DNS_TAG)["filter"]) == 6
        assert firewall.unprotect_dns()
        run_command(["iptables", "-D", "INPUT", "-p", "udp", "--dport", "1053", "-j", "ACCEPT"])
        print("PASS: all VPN DNS redirects to dnsfilter; its private port guard survives VPN shutdown")

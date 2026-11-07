"""Explicit integration entry point; requires a disposable systemd container."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "files"), str(ROOT / "filter_plugins")]
from wireguard import FilterModule
from wireguard_firewall import OperationError, run_command
from wireguard_manager import WireGuardManager, atomic_write


def main():
    expected = os.environ.get("WG_RELEASE_HOST_NETNS")
    if not expected or os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == expected or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise SystemExit("Run only through the disposable integration container")
    environment = Environment(loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined)
    environment.filters.update(FilterModule().filters())
    directory = Path("/etc/wireguard")
    directory.mkdir(mode=0o700, exist_ok=True)
    config = directory / "wg0.conf"
    if config.exists():
        raise SystemExit("Integration tests require a fresh container without an existing wg0.conf")
    # Give the isolated fixture a local route for automatic WAN discovery. A
    # dummy link and --network=none cannot reach the host or the Internet.
    run_command(["ip", "link", "add", "wan0", "type", "dummy"])
    run_command(["ip", "address", "add", "192.0.2.1/24", "dev", "wan0"])
    run_command(["ip", "link", "set", "wan0", "up"])
    run_command(["ip", "-4", "route", "add", "default", "dev", "wan0"])
    from test_native_firewall import run_tests
    from test_apparmor_policy import check_profile_syntax
    check_profile_syntax()
    run_tests(environment)
    platform_checks(environment)
    if sys.argv[1:] == ["--firewall-only"]:
        return
    try:
        run_command(["wg", "show", "interfaces"])
    except OperationError as error:
        raise SystemExit("Native WireGuard is blocked in this test environment. Inspect host AppArmor/netlink permissions; use a compatible disposable Linux test host. No host policy was changed.") from error
    private = run_command(["wg", "genkey"]).strip()
    atomic_write(directory / "privatekey", private)
    values = dict(wireguard_address="10.99.0.1/24", wireguard_port=51820, wireguard_mtu=1280,
                  server_priv_key_final=private, ansible_facts={"default_ipv4": {"interface": "wan0"}}, dns_server="1.1.1.1")
    original = environment.get_template("wg0.conf.j2").render(**values).rstrip() + "\n"
    atomic_write(config, original)
    stage = directory / "stage"
    stage.mkdir(mode=0o700)
    candidate = stage / "wg0.conf"
    atomic_write(candidate, original)
    manager = WireGuardManager(directory)

    # Native systemd invokes the real wg-quick and the installed firewall helper.
    bindir = Path("/tmp/wg-release-bin")
    bindir.mkdir()
    marker = directory / ".inject-firewall-failure"
    wrapper = bindir / "iptables-restore"
    wrapper.write_text('''#!/usr/bin/python3
import os, pathlib, signal, subprocess, sys
data = sys.stdin.read()
marker = pathlib.Path('/etc/wireguard/.inject-firewall-failure')
if marker.exists() and '--to-destination 2.2.2.2:53' in data:
    mode = marker.read_text()
    marker.unlink()
    if mode == 'kill':
        partial = '\\n'.join(line for line in data.splitlines() if '-p tcp ' not in line) + '\\n'
        subprocess.run(['/usr/sbin/iptables-restore', *sys.argv[1:]], input=partial, text=True, check=True)
        os.kill(os.getppid(), signal.SIGKILL)
        sys.exit(0)
    data = data.replace('-j DNAT', '-j NONEXISTENT_TARGET')
result = subprocess.run(['/usr/sbin/iptables-restore', *sys.argv[1:]], input=data, text=True)
sys.exit(result.returncode)
''')
    wrapper.chmod(0o700)
    dropin = Path("/etc/systemd/system/wg-quick@wg0.service.d")
    dropin.mkdir(parents=True)
    (dropin / "test.conf").write_text('[Service]\nEnvironment="PATH=/tmp/wg-release-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n')
    run_command(["systemctl", "daemon-reload"])
    run_command(["iptables", "-A", "FORWARD", "-i", "wan0", "-m", "comment", "--comment", "unrelated-release-rule", "-j", "ACCEPT"])
    run_command(["systemctl", "start", "wg-quick@wg0"])
    assert "wg0" in run_command(["wg", "show", "interfaces"]).split()
    assert manager.firewall.up("1.1.1.1", "wan0") is False
    previous_rules = manager.firewall.owned_rules()
    assert sum(len(lines) for lines in previous_rules.values()) == 4

    atomic_write(candidate, environment.get_template("wg0.conf.j2").render(**dict(values, dns_server="2.2.2.2")))
    for mode in ("error", "kill"):
        marker.write_text(mode)
        try:
            manager.apply(candidate)
        except OperationError as error:
            assert "previous configuration was restored" in str(error), str(error)
        else:
            raise AssertionError("Injected failed startup was reported as successful")
        assert not marker.exists(), "Failure injection was not exercised"
        assert config.read_text() == original
        assert run_command(["systemctl", "is-active", "wg-quick@wg0"]).strip() == "active"
        assert manager.firewall.owned_rules() == previous_rules
        assert "unrelated-release-rule" in run_command(["iptables-save", "-t", "filter"])
        assert "2.2.2.2:53" not in run_command(["iptables-save", "-t", "nat"])
        print(f"PASS: native systemd/WireGuard rollback after firewall {mode}")

    atomic_write(candidate, original)
    profile_template = stage / "client.template"
    profile_template.write_text(environment.get_template("client.conf.j2").render(
        client_address="$WG_CLIENT_ADDRESS", client_private_key={"stdout": "$WG_CLIENT_PRIVATE_KEY"},
        server_public_key={"stdout": "$WG_SERVER_PUBLIC_KEY"}, wireguard_gateway_ip="$WG_GATEWAY_IP",
        wireguard_port="$WG_SERVER_PORT", ansible_host="2001:db8::1",
    ))
    manager.add("alice", profile_template)
    public = manager.profile_keys((directory / "alice.conf").read_text())[1]
    managed = config.read_text()
    (directory / "alice.conf").unlink()
    atomic_write(config, managed + f"\n[Peer]\nPublicKey = {public}\nAllowedIPs = 10.99.0.3/32\n")
    manager.sync()
    try:
        manager.remove("alice")
    except OperationError as error:
        assert "unmanaged" in str(error)
    else:
        raise AssertionError("Unmanaged duplicate bypassed revocation checks")
    assert public in run_command(["wg", "show", "wg0", "peers"]).split()
    atomic_write(config, managed)
    manager.remove("alice")
    assert public not in run_command(["wg", "show", "wg0", "peers"]).split()
    print("PASS: missing-profile revocation with real kernel peers")

    manager.add("bob", profile_template)
    public = manager.profile_keys((directory / "bob.conf").read_text())[1]
    run_command(["wg", "set", "wg0", "peer", public, "remove"])
    assert manager.apply(candidate)["changed"] is False
    assert public in run_command(["wg", "show", "wg0", "peers"]).split()
    run_command(["ip", "link", "delete", "wg0"])
    assert run_command(["systemctl", "is-active", "wg-quick@wg0"]).strip() == "active"
    manager.apply(candidate)
    assert public in run_command(["wg", "show", "wg0", "peers"]).split()
    assert manager.firewall.owned_rules() == previous_rules
    print("PASS: unchanged setup repairs peer drift and a missing interface")

    run_command(["systemctl", "stop", "wg-quick@wg0"])
    assert not any(manager.firewall.owned_rules().values())
    print("PASS: service shutdown removes owned rules and preserves unrelated rules")


def platform_checks(environment):
    from test_native_ssh import run_tests as ssh_checks
    ssh_checks(ROOT)

    # A journal-only server has no auth.log. Exercise the exact jail generated
    # by the playbook with the installed daemon, including its systemd backend.
    import yaml
    install = yaml.safe_load((ROOT / "tasks/install_dnsfilter.yml").read_text())
    block = next(task["block"] for task in install if "block" in task)
    port_check = next(task["ansible.builtin.command"]["argv"] for task in block
                      if task["name"] == "Check reserved ports before the first installation")
    assert not run_command(port_check).strip()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
        udp.bind(("127.0.0.1", 1053))
        tcp.bind(("127.0.0.1", 18080))
        tcp.listen()
        ports = run_command(port_check)
        assert "127.0.0.1:1053" in ports and "127.0.0.1:18080" in ports, ports
    print("PASS: DNS preflight detects occupied UDP and TCP ports")

    hardening = yaml.safe_load((ROOT / "server_hardening.yml").read_text())[0]
    jail = next(task["copy"]["content"] for task in hardening["tasks"] if task["name"] == "Configure Fail2Ban to protect SSH")
    Path("/etc/fail2ban/jail.local").write_text(environment.from_string(jail).render(ansible_port=2222))
    run_command(["fail2ban-client", "-t"])
    run_command(["systemctl", "start", "fail2ban"])
    for attempt in range(30):
        try:
            status = run_command(["fail2ban-client", "status", "sshd"])
            break
        except OperationError:
            time.sleep(0.1)
    else:
        raise AssertionError("Fail2Ban SSH jail did not start")
    assert "Journal matches" in status
    print("PASS: Fail2Ban starts against the systemd journal")

    # Use Debian's actual unattended-upgrades matcher, not a test reimplementation.
    with tempfile.TemporaryDirectory() as temporary:
        for distribution, codename in (("Debian", "trixie"), ("Ubuntu", "noble")):
            policy = Path(temporary) / "policy"
            policy.write_text(environment.get_template("unattended-upgrades.j2").render(ansible_facts={"distribution": distribution}))
            code = '''
import apt_pkg, importlib.machinery, types, sys
loader = importlib.machinery.SourceFileLoader("upgrader", "/usr/bin/unattended-upgrade")
module = types.ModuleType(loader.name)
loader.exec_module(module)
distribution, codename, filename = sys.argv[1:]
module.substitute = lambda value: value.replace("${distro_id}", distribution).replace("${distro_codename}", codename)
config = apt_pkg.Configuration()
apt_pkg.read_config_file(config, filename)
patterns = list(config.value_list("Unattended-Upgrade::Origins-Pattern"))
for entry in config.value_list("Unattended-Upgrade::Allowed-Origins"):
    origin, archive = entry.split(":", 1)
    patterns.append("origin=" + origin + ",archive=" + archive)
origin = types.SimpleNamespace(origin=distribution, label="Debian-Security" if distribution == "Debian" else "Ubuntu", archive="stable-security" if distribution == "Debian" else codename + "-security", codename=codename + "-security" if distribution == "Debian" else codename, component="main", site="security.example.org")
assert any(module.match_whitelist_string(pattern, origin) for pattern in patterns), patterns
origin.origin = "Untrusted-Third-Party"
assert not any(module.match_whitelist_string(pattern, origin) for pattern in patterns)
'''
            run_command(["/usr/bin/python3", "-c", code, distribution, codename, str(policy)])
    print("PASS: Debian and Ubuntu security origins match the installed updater")

    # UFW may load its sysctl file on activation. Network sysctls are deliberately
    # read-only in this fixture; this test exercises rule loading, not forwarding.
    Path("/etc/ufw/sysctl.conf").write_text("# Integration fixture: no sysctl writes\n")
    dnsfilter_config = Path("/etc/wireguard-dnsfilter/config.yml")
    dnsfilter_config.parent.mkdir(exist_ok=True)
    dnsfilter_config.write_text("# Fixture marks the managed DNS filter as installed\n")
    run_command(["ufw", "allow", "53"])
    run_command(["ufw", "allow", "8080/tcp"])
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "templates").symlink_to(ROOT / "templates", target_is_directory=True)
        playbook = root / "firewall.yml"
        playbook.write_text(yaml.safe_dump([{
            "hosts": "localhost", "gather_facts": False,
            "vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                     "ssh_port": 2222, "wireguard_port": 51820},
            "tasks": [{"ansible.builtin.import_tasks": str(ROOT / "tasks/wireguard_firewall_rules.yml")}],
        }]))
        for attempt in range(2):
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)],
                                    env=dict(os.environ, ANSIBLE_FILTER_PLUGINS=str(ROOT / "filter_plugins")),
                                    text=True, capture_output=True, timeout=90)
            assert result.returncode == 0, result.stdout + result.stderr
        for executable, chain in (("iptables-save", "ufw-before-input"), ("ip6tables-save", "ufw6-before-input")):
            rules = run_command([executable, "-t", "filter"]).splitlines()
            inputs = [line for line in rules if line.startswith(f"-A {chain} ")]
            assert inputs[0] == f"-A {chain} -j wg-private-services", inputs
            drops = [line for line in rules if line.startswith("-A wg-private-services ") and line.endswith(" -j DROP")]
            assert len(drops) == 3, drops
            inputs = [line for line in rules if line.startswith("-A INPUT ")]
            assert all("wireguard-manager:dnsfilter" in line for line in inputs[:6]), inputs
    run_command(["ufw", "disable"])
    print("PASS: real Ansible/UFW loads IPv4 and IPv6 guards before legacy public allows")


if __name__ == "__main__":
    main()

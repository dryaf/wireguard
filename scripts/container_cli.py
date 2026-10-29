"""Container-side commands; host Make targets never execute Python or Ansible."""

import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "/run/wireguard/inventory.ini"
KNOWN_HOSTS = Path("/run/wireguard/known_hosts")
PLAYBOOKS = {
    "vpn-server-setup": "wireguard_server_setup.yml",
    "vpn-server-status": "wireguard_server_status.yml",
    "vpn-firewall-setup": "server_firewall_setup.yml",
    "vpn-client-add": "wireguard_client_add.yml",
    "vpn-client-remove": "wireguard_client_remove.yml",
    "vpn-client-qrcode": "wireguard_client_qrcode.yml",
    "vpn-client-list": "wireguard_client_list.yml",
    "vpn-debug": "server_debug_vpn.yml",
    "server-hardening": "server_hardening.yml",
    "enable-auto-upgrades": "server_toggle_autoupgrades.yml",
    "disable-auto-upgrades": "server_toggle_autoupgrades.yml",
    "dnsfilter-status": "wireguard_dnsfilter.yml",
}
DNSFILTER_CHANGES = {
    f"dnsfilter-{action}-{category}": {"dnsfilter_category": category, "dnsfilter_value": action == "enable"}
    for category in ("ads", "porn", "malware") for action in ("enable", "disable")
}
PLAYBOOKS.update({command: "wireguard_dnsfilter.yml" for command in DNSFILTER_CHANGES})


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def prompt(label, variable=None, default=""):
    if variable is not None and variable in os.environ:
        return os.environ[variable]
    return input(label) or default


def ask_dnsfilter():
    label = "Use dnsfilter for all VPN clients (keep saved policy; first install blocks malware only)? [y/N]: "
    while True:
        answer = prompt(label, "DNSFILTER", "no").strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        if "DNSFILTER" in os.environ:
            raise ValueError("DNSFILTER must be yes or no")
        print("Please answer yes or no.")


def valid_host(host):
    if not re.fullmatch(r"[A-Za-z0-9_.:%-]+", host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return len(host) <= 253 and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in host.rstrip(".").split(".")
        )


def init():
    path = Path(INVENTORY)
    if path.stat().st_size:
        raise ValueError("Refusing to overwrite an existing inventory")
    host = prompt("Server host: ")
    user = prompt("SSH username (default: root): ", default="root")
    port = int(prompt("SSH port (default: 22): ", default="22"))
    if not valid_host(host) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user) or not 1 <= port <= 65535:
        raise ValueError("Invalid hostname, username or SSH port")
    path.write_text(f"[servers]\nvpn ansible_host={host} ansible_user={user} ansible_port={port}\n")
    print("Inventory created. Run make trust-host with the server's fingerprint from a trusted source.")


def servers():
    result = run("ansible-inventory", "-i", INVENTORY, "--list", text=True, stdout=subprocess.PIPE)
    inventory = json.loads(result.stdout)
    names, visited = set(), set()

    def visit(group):
        if group in visited:
            return
        visited.add(group)
        data = inventory.get(group, {})
        names.update(data.get("hosts", []))
        for child in data.get("children", []):
            visit(child)

    visit("servers")
    if not names:
        raise ValueError("The inventory contains no hosts in the servers group")
    result = []
    for name in sorted(names):
        variables = inventory.get("_meta", {}).get("hostvars", {}).get(name, {})
        host = str(variables.get("ansible_host", name))
        port = int(variables.get("ansible_port", 22))
        if not valid_host(host) or not 1 <= port <= 65535:
            raise ValueError(f"Invalid SSH endpoint for {name}")
        result.append((name, host, port, variables))
    return result


def known_host_name(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def fingerprint_from_console(value):
    """Accept a SHA-256 token or one ED25519 ssh-keygen fingerprint line."""
    value = value.strip()
    fields = value.split()
    fingerprint = ""
    if "\n" not in value and "\r" not in value and value.count("SHA256:") == 1:
        if len(fields) == 1:
            fingerprint = fields[0]
        elif len(fields) >= 3 and fields[0] == "256" and fields[-1] == "(ED25519)":
            # Only the fingerprint field carries trust. Never search the comment
            # for a matching value or accept several pasted fingerprint records.
            fingerprint = fields[1]
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise ValueError("Invalid fingerprint format: paste the SHA256:... value or one full ED25519 "
                         "fingerprint line from the server console; known_hosts was not changed")
    return fingerprint


def update_known_hosts(trust):
    # ssh-keygen replaces files by renaming. Work on a temporary copy because
    # the persistent known_hosts file is an individual bind mount.
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary) / "known_hosts"
        destination.write_bytes(KNOWN_HOSTS.read_bytes())
        for name, host, port, _ in servers():
            keys = ""
            if trust:
                keys = run("ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519", host,
                           text=True, stdout=subprocess.PIPE).stdout
                if not keys.strip():
                    raise ValueError(f"No ED25519 host key received from {name}")
                candidate = Path(temporary) / "candidate"
                candidate.write_text(keys)
                fingerprints = run("ssh-keygen", "-E", "sha256", "-lf", str(candidate), text=True, stdout=subprocess.PIPE).stdout
                print(f"{name} ({host}:{port}):\n{fingerprints}", end="")
                expected = fingerprint_from_console(input(
                    "Paste the fingerprint from the server console/provider (SHA256:... or full ED25519 line): "))
                actual = {line.split()[1] for line in fingerprints.splitlines()}
                if actual != {expected}:
                    raise ValueError("Fingerprint mismatch; known_hosts was not changed")
            run("ssh-keygen", "-f", str(destination), "-R", known_host_name(host, port))
            if trust:
                with destination.open("a") as output:
                    output.write("\n" + keys)
        KNOWN_HOSTS.write_bytes(destination.read_bytes())


def monitor(dnsfilter_only=False, follow=True):
    name, host, port, variables = servers()[0]
    user = str(variables.get("ansible_user", ""))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
        raise ValueError(f"Set a valid ansible_user for {name}")
    print(f"{'Following logs for' if follow else 'Recent logs for'} {name} ({host}:{port})", flush=True)
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "Compression=no", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-p", str(port), "-l", user]
    if sys.stdin.isatty():
        args.append("-t")
    args.extend(shlex.split(str(variables.get("ansible_ssh_common_args", ""))))
    journal = ["journalctl", "--no-pager", "--output=short-iso", "--lines=100"]
    if follow:
        journal.append("--follow")
    # Podman's conmon may use a separate systemd scope. Include its journal
    # records explicitly, retaining logs from containers removed after restart.
    journal.extend(["_SYSTEMD_UNIT=wireguard-dnsfilter.service", "+", "CONTAINER_NAME=wireguard-dnsfilter"])
    if not dnsfilter_only:
        journal.extend(["+", "_SYSTEMD_UNIT=wg-quick@wg0.service"])
    if user != "root":
        journal[:0] = ["sudo", "-n", "--"]
    args.extend([host, shlex.join(journal)])
    os.execvp(args[0], args)


def check_ssh():
    for name, host, port, variables in servers():
        user = str(variables.get("ansible_user", ""))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
            raise ValueError(f"Set a valid ansible_user for {name}")
        args = ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "Compression=no", "-o", "ForwardAgent=no",
                "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-p", str(port), "-l", user]
        args.extend(shlex.split(str(variables.get("ansible_ssh_common_args", ""))))
        run(*args, host, "true" if user == "root" else "sudo -n true")
        print(f"Verified key-only SSH and required administrator access: {name} ({host}:{port})")


def main(command, extra):
    if command in PLAYBOOKS:
        args = ["ansible-playbook", "-i", INVENTORY, PLAYBOOKS[command]]
        if command in {"vpn-client-add", "vpn-client-remove", "vpn-client-qrcode"}:
            os.environ["CLIENT_NAME"] = prompt("Client name: ", "CLIENT_NAME")
        if command == "vpn-server-setup":
            settings = {"dnsfilter_enabled": ask_dnsfilter()}
            if not settings["dnsfilter_enabled"]:
                settings["dns_server"] = str(ipaddress.IPv4Address(prompt("DNS server (default: 1.1.1.1): ", "DNS_SERVER", "1.1.1.1")))
            args.extend(["--extra-vars", json.dumps(settings)])
        if command in {"enable-auto-upgrades", "disable-auto-upgrades"}:
            args.extend(["--extra-vars", json.dumps({"enabled": "yes" if command == "enable-auto-upgrades" else "no"})])
        if command in DNSFILTER_CHANGES:
            args.extend(["--extra-vars", json.dumps({"dnsfilter_action": "update", **DNSFILTER_CHANGES[command]})])
        run(*args, *extra)
    elif command == "playbook":
        if not extra:
            raise ValueError("Usage: scripts/container playbook PLAYBOOK.yml [ANSIBLE_ARGS...]")
        run("ansible-playbook", "-i", INVENTORY, *extra)
    elif command == "test":
        run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v", *extra)
    elif command == "dnsfilter-test":
        run(sys.executable, "tests/test_dnsfilter_integration.py", *extra)
    elif command == "syntax-check":
        for path in sorted((*ROOT.glob("server_*.yml"), *ROOT.glob("wireguard_*.yml"))):
            run("ansible-playbook", "-i", "localhost,", "--syntax-check", str(path))
    elif command == "audit":
        run("pip-audit", "--strict", "--require-hashes", "-r", "locks/requirements-dev.lock", *extra)
    elif command == "deps-check":
        run(sys.executable, "scripts/dependency_lock.py", "check")
        run(sys.executable, "-m", "pip", "check")
    elif command == "check-auto-upgrades":
        for shell_command in ("apt-config dump | grep 'APT::Periodic'", "systemctl status unattended-upgrades --no-pager"):
            run("ansible", "-i", INVENTORY, "servers", "-b", "-m", "ansible.builtin.shell", "-a", shell_command)
    elif command == "init":
        init()
    elif command == "check-ssh":
        check_ssh()
    elif command in {"trust-host", "clean_known_hosts"}:
        update_known_hosts(trust=command == "trust-host")
    elif command == "vpn-monitor":
        monitor()
    elif command in {"dnsfilter-logs", "dnsfilter-monitor"}:
        monitor(dnsfilter_only=True, follow=command == "dnsfilter-monitor")
    else:
        raise ValueError(f"Unknown command: {command}")


if __name__ == "__main__":
    os.chdir(ROOT)
    try:
        Path("/tmp/wireguard").mkdir(mode=0o700, exist_ok=True)
        main(sys.argv[1], sys.argv[2:])
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
    except (ValueError, OSError, EOFError) as error:
        sys.exit(str(error))

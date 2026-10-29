#!/usr/bin/env python3
"""Idempotent wg0 hooks; touch only rules carrying this project's ownership tag."""

import argparse
from collections import Counter
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

from wireguard import wireguard_interface, wireguard_ipv4, wireguard_number

TAG = "wireguard-manager:wg0"
DNS_TAG = "wireguard-manager:dnsfilter"
DNS_PORT = 1053
HELPER = "/usr/local/lib/wireguard-manager/wireguard_firewall.py"


class OperationError(Exception):
    pass


def run_command(argv, stdin=None):
    try:
        result = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperationError(f"Unable to complete {argv[0]} operation") from error
    if result.returncode:
        # A rejected WireGuard configuration can contain private key material.
        raise OperationError(f"{argv[0]} operation failed (exit {result.returncode})")
    return result.stdout


def managed_policy(config):
    hooks = {key: [] for key in ("preup", "predown", "postup", "postdown")}
    for line in config.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().lower() in hooks:
            hooks[key.strip().lower()].append(value.strip())
    if not any(hooks.values()):
        return None
    if hooks["preup"] or hooks["predown"] or len(hooks["postup"]) != 1 or len(hooks["postdown"]) != 1:
        raise OperationError("New interface configurations must use the managed firewall hooks")
    up, down = shlex.split(hooks["postup"][0]), shlex.split(hooks["postdown"][0])
    if len(up) not in (6, 8) or up[:3] != [HELPER, "up", "--dns"] or up[4] != "--wan" or down != [HELPER, "down"]:
        raise OperationError("Unrecognized firewall hook; refusing arbitrary shell commands")
    policy = (wireguard_ipv4(up[3]), wireguard_interface(up[5]))
    if len(up) == 8:
        if up[6] != "--dns-port":
            raise OperationError("Unrecognized DNS port option")
        return (*policy, wireguard_number(up[7], 1, 65535))
    return policy


class WireGuardFirewall:
    def __init__(self, directory="/etc/wireguard", runner=run_command):
        self.directory = Path(directory)
        self.run = runner

    @contextmanager
    def locked(self):
        # This is deliberately separate from .management.lock: wg-quick invokes
        # the hooks while the parent apply process holds the management lock.
        fd = os.open(self.directory / ".firewall.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + 25
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OperationError("Another WireGuard firewall operation is still running")
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)

    def owned_rules(self, tag=TAG, ipv6=False):
        owned = {}
        for table in (("filter",) if ipv6 else ("filter", "nat")):
            owned[table] = []
            for line in self.run(["ip6tables-save" if ipv6 else "iptables-save", "-t", table]).splitlines():
                if not line.startswith("-A "):
                    continue
                fields = shlex.split(line)
                if "--comment" in fields and fields[fields.index("--comment") + 1] == tag:
                    owned[table].append(line)
        return owned

    def restore(self, rules, ipv6=False):
        text = "".join(f"*{table}\n" + "\n".join(lines) + "\nCOMMIT\n" for table, lines in rules.items() if lines)
        if text:
            self.run(["ip6tables-restore" if ipv6 else "iptables-restore", "--wait", "10", "--noflush"], stdin=text)

    def clear(self, tag=TAG, ipv6=False):
        changed = False
        # A concurrent UFW reload can remove a rule between save and restore.
        # Re-read in that case; never flush an entire table or an unowned rule.
        for attempt in range(3):
            rules = self.owned_rules(tag, ipv6)
            if not any(rules.values()):
                return changed
            changed = True
            try:
                self.restore({table: [line.replace("-A ", "-D ", 1) for line in lines] for table, lines in rules.items()}, ipv6)
            except OperationError:
                if attempt == 2:
                    raise
        if any(self.owned_rules(tag, ipv6).values()):
            raise OperationError("Unable to remove all managed WireGuard firewall rules")
        return changed

    def down(self):
        with self.locked():
            return self.clear()

    def protect_dns(self):
        """Keep the unprivileged DNS port private, even without UFW enabled."""
        wanted = []
        for protocol in ("udp", "tcp"):
            suffix = f"-p {protocol} -m {protocol} --dport {DNS_PORT} -m comment --comment {DNS_TAG}"
            wanted.extend([
                f"-A INPUT -i lo {suffix} -j ACCEPT",
                f"-A INPUT -i wg0 {suffix} -j ACCEPT",
                f"-A INPUT {suffix} -j DROP",
            ])
        with self.locked():
            changed = False
            # Go can use a dual-stack listener for a wildcard IPv4 address.
            # Protect both families before allowing the service to start.
            for ipv6 in (False, True):
                current = self.owned_rules(DNS_TAG, ipv6)
                inputs = [line for line in self.run(["ip6tables-save" if ipv6 else "iptables-save", "-t", "filter"]).splitlines() if line.startswith("-A INPUT ")]
                normalized = lambda lines: [shlex.split(line) for line in lines]
                if normalized(inputs[:len(wanted)]) == normalized(wanted) and normalized(current["filter"]) == normalized(wanted):
                    continue
                # One filter-table transaction per family: do not open the port
                # while replacing a guard, even with existing public ACCEPTs.
                changes = [line.replace("-A ", "-D ", 1) for line in current["filter"]]
                changes.extend(line.replace("-A INPUT ", "-I INPUT 1 ", 1) for line in reversed(wanted))
                self.restore({"filter": changes}, ipv6)
                changed = True
            return changed

    def unprotect_dns(self):
        with self.locked():
            ipv4 = self.clear(DNS_TAG)
            ipv6 = self.clear(DNS_TAG, ipv6=True)
            return ipv4 or ipv6

    def up(self, dns, wan, dns_port=53):
        dns, wan = wireguard_ipv4(dns), wireguard_interface(wan)
        dns_port = wireguard_number(dns_port, 1, 65535)
        if dns_port == DNS_PORT:
            self.protect_dns()
        comment = f"-m comment --comment {TAG}"
        wanted = {
            "filter": [f"-A FORWARD -i wg0 {comment} -j ACCEPT"],
            "nat": [
                f"-A POSTROUTING -o {wan} {comment} -j MASQUERADE",
                *[f"-A PREROUTING -i wg0 -p {protocol} -m {protocol} --dport 53 {comment} -j DNAT --to-destination {dns}:{dns_port}" for protocol in ("udp", "tcp")],
            ],
        }
        with self.locked():
            current = self.owned_rules()
            normalize = lambda rules: {table: Counter(tuple(shlex.split(line)) for line in lines) for table, lines in rules.items()}
            if normalize(current) == normalize(wanted):
                return False
            self.clear()
            try:
                self.restore(wanted)
            except (OperationError, OSError) as error:
                try:
                    self.clear()
                except (OperationError, OSError) as cleanup:
                    raise OperationError("WireGuard firewall update and cleanup failed") from cleanup
                raise error
            return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="/etc/wireguard")
    commands = parser.add_subparsers(dest="operation", required=True)
    up = commands.add_parser("up")
    up.add_argument("--dns", required=True)
    up.add_argument("--wan", required=True)
    up.add_argument("--dns-port", type=int, default=53)
    commands.add_parser("down")
    commands.add_parser("protect-dns")
    commands.add_parser("unprotect-dns")
    args = parser.parse_args()
    try:
        firewall = WireGuardFirewall(args.directory)
        if args.operation == "up":
            changed = firewall.up(args.dns, args.wan, args.dns_port)
        else:
            changed = getattr(firewall, args.operation.replace("-", "_"))()
        print(json.dumps({"ok": True, "changed": changed}))
    except (OperationError, ValueError, OSError) as error:
        parser.exit(1, f"WireGuard firewall failed: {error}\n")

#!/usr/bin/python3
"""Read-only wg0 diagnostics; no keys, configuration writes or service restarts."""

import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.request


def run(argv):
    """Bound every probe, including missing utilities and wedged services."""
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=12)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{argv[0]} is not installed"
    except (OSError, subprocess.TimeoutExpired):
        return 126, "", f"{argv[0]} could not run or timed out"


def interface_settings(path):
    # Never print the configuration: it contains private and preshared keys.
    settings = {}
    section = ""
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            section = line.lower()
        key, separator, value = line.partition("=")
        if section == "[interface]" and separator and key.strip().lower() in {"address", "listenport", "mtu", "postup"}:
            settings.setdefault(key.strip().lower(), []).append(value.strip())
    return settings


def managed_hook(settings):
    """Read known hook arguments as data; never execute configuration hooks."""
    for value in settings.get("postup", []):
        args = shlex.split(value)
        if args[:2] == ["/usr/local/lib/wireguard-manager/wireguard_firewall.py", "up"]:
            if len(args) not in (6, 8) or args[2] != "--dns" or args[4] != "--wan":
                raise ValueError("Invalid managed hook arguments")
            dns = str(ipaddress.IPv4Address(args[3]))
            if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.:-]{0,14}", args[5]):
                raise ValueError("Invalid WAN interface")
            port = 53
            if len(args) == 8:
                if args[6] != "--dns-port" or not 1 <= int(args[7]) <= 65535:
                    raise ValueError("Invalid DNS port")
                port = int(args[7])
            return dns, args[5], port
    return None


class Diagnostics:
    def __init__(self, root=Path("/"), runner=run):
        self.root = root
        self.run = runner
        self.failures = 0

    def report(self, status, name, detail, hint=""):
        self.failures += status == "FAIL"
        print(f"[{status}] {name}: {detail}")
        if hint:
            print(f"  Next: {hint}")

    def probe(self, name, argv, required=True):
        rc, out, err = self.run(argv)
        self.report("INFO" if rc == 0 else ("FAIL" if required else "WARN"), name,
                    out or err or f"exit {rc}")
        return rc, out

    def expect(self, name, argv, expected, hint):
        rc, out, err = self.run(argv)
        ok = rc == 0 and out == expected
        self.report("PASS" if ok else "FAIL", name, out or err or f"exit {rc}", "" if ok else hint)
        return ok

    def persistent_forwarding(self):
        # Show provenance, rather than claim to simulate all boot-time loaders.
        # UFW and systemd-sysctl may load different files at different times.
        paths = [self.root / "etc/sysctl.conf", self.root / "etc/ufw/sysctl.conf"]
        for directory in ("usr/lib", "usr/local/lib", "run", "etc"):
            paths.extend(sorted((self.root / directory / "sysctl.d").glob("*.conf")))
        found = []
        for path in paths:
            try:
                for number, line in enumerate(path.read_text().splitlines(), 1):
                    setting = re.sub(r"[#;].*$", "", line).strip()
                    key, separator, value = setting.partition("=")
                    key = key.strip().lstrip("-").replace("/", ".")
                    if separator and key in {"net.ipv4.ip_forward", "net.ipv4.conf.all.forwarding", "net.ipv6.conf.all.forwarding"}:
                        source = f"/{path.relative_to(self.root)}:{number}: {setting}"
                        found.append(source)
                        if value.strip() == "0":
                            self.report("WARN", "Persistent forwarding override", source,
                                        "Review sysctl load order and UFW settings before the next reboot/reload.")
            except FileNotFoundError:
                continue
            except OSError:
                self.report("WARN", "Persistent forwarding", f"Cannot read /{path.relative_to(self.root)}")
        self.report("INFO" if found else "WARN", "Forwarding definitions on disk",
                    "\n  " + "\n  ".join(found) if found else "No persistent forwarding definitions found",
                    "Definitions are evidence only; file precedence and later services determine the boot value.")

    def firewall(self, hook, wan):
        self.probe("iptables backend", ["iptables", "--version"])
        for table, chain in (("filter", "FORWARD"), ("nat", "POSTROUTING"), ("nat", "PREROUTING")):
            self.probe(f"{table}/{chain} rules and counters",
                       ["iptables", "-w", "5", "-t", table, "-L", chain, "-n", "-v", "--line-numbers"])
        self.probe("UFW policy", ["ufw", "status", "verbose"], required=False)
        self.probe("IPv4 filter chains (including return-traffic rules)", ["iptables", "-w", "5", "-S"])
        self.probe("nftables rules (including rules outside iptables)", ["nft", "list", "ruleset"], required=False)
        if hook:
            dns, configured_wan, port = hook
            egress = wan or configured_wan
            if configured_wan == "auto":
                self.report("PASS" if wan else "FAIL", "Hook WAN interface",
                            f"automatic detection at start; current Internet route={wan or 'unavailable'}")
            elif wan:
                self.report("PASS" if wan == configured_wan else "FAIL", "Hook WAN interface",
                            f"configured={configured_wan}, current Internet route={wan}",
                            "" if wan == configured_wan else "Update the PostUp WAN interface and restore its NAT rule.")
            tag = ["-m", "comment", "--comment", "wireguard-manager:wg0"]
            rules = [
                ("VPN forwarding rule", "filter", "FORWARD", ["-i", "wg0", *tag, "-j", "ACCEPT"]),
                ("Internet masquerade rule", "nat", "POSTROUTING", ["-o", egress, *tag, "-j", "MASQUERADE"]),
                *[(f"DNS redirect ({protocol})", "nat", "PREROUTING",
                   ["-i", "wg0", "-p", protocol, "-m", protocol, "--dport", "53", *tag,
                    "-j", "DNAT", "--to-destination", f"{dns}:{port}"]) for protocol in ("udp", "tcp")],
            ]
            for name, table, chain, rule in rules:
                rc, _, err = self.run(["iptables", "-w", "5", "-t", table, "-C", chain, *rule])
                detail = "Managed rule present" if rc == 0 else (err or "Managed rule missing")
                if chain == "POSTROUTING":
                    detail = f"WAN {egress}: {detail}"
                self.report("PASS" if rc == 0 else "FAIL", name,
                            detail,
                            "" if rc == 0 else "Review the wg-quick startup failure and restore the managed firewall hooks.")
        else:
            self.report("WARN", "Firewall rule validation", "No recognized managed PostUp hook",
                        "Review the rules above for wg0 forwarding, established return traffic, WAN masquerading and DNS DNAT.")
        self.report("WARN", "Firewall reachability", "Rule presence alone does not verify packet traversal",
                    "Review rule order, return traffic, native nftables chains and the VPS provider firewall; test from a VPN client.")

    def check(self):
        self.probe("Running kernel", ["uname", "-r"])
        settings, hook = {}, None
        try:
            settings = interface_settings(self.root / "etc/wireguard/wg0.conf")
            hook = managed_hook(settings)
            self.report("PASS", "wg0 configuration", "Readable; keys omitted")
        except (OSError, ValueError):
            self.report("FAIL", "wg0 configuration", "Missing, unreadable or invalid managed hook",
                        "Inspect /etc/wireguard/wg0.conf privately; do not paste private keys into logs.")

        self.expect("WireGuard service", ["systemctl", "is-active", "wg-quick@wg0"], "active",
                    "Inspect sudo journalctl -b -u wg-quick@wg0 and kernel/AppArmor errors privately.")
        self.expect("WireGuard starts at boot", ["systemctl", "is-enabled", "wg-quick@wg0"], "enabled",
                    "Review whether wg-quick@wg0 should be enabled for this VPS.")
        rc, link = self.probe("wg0 link/address/MTU", ["ip", "-details", "-4", "address", "show", "dev", "wg0"])
        if rc:
            self.probe("WireGuard module for running kernel", ["modinfo", "wireguard"], required=False)
        else:
            flags = re.search(r"wg0:\s+<([^>]+)>", link)
            up = bool(flags and "UP" in flags[1].split(","))
            self.report("PASS" if up else "FAIL", "wg0 administrative state", "UP" if up else "DOWN or unavailable")
        if settings.get("address"):
            for address in settings["address"]:
                for value in address.split(","):
                    try:
                        configured = ipaddress.ip_interface(value.strip())
                        if configured.version == 4 and rc == 0:
                            present = str(configured) in link.split()
                            self.report("PASS" if present else "FAIL", "Configured VPN address",
                                        f"{configured}: {'present' if present else 'missing from wg0'}")
                    except ValueError:
                        self.report("FAIL", "VPN address", "Invalid address in wg0.conf")
        if settings.get("mtu") and rc == 0:
            mtu = settings["mtu"][-1]
            live_mtu = re.search(r"\bmtu (\d+)\b", link)
            self.report("PASS" if live_mtu and live_mtu[1] == mtu else "FAIL", "Configured MTU", f"Expected {mtu}; see wg0 above")
        port_rc, port = self.probe("WireGuard UDP listen port", ["wg", "show", "wg0", "listen-port"])
        if port_rc == 0:
            expected = settings.get("listenport", [port])[-1]
            self.report("PASS" if port != "0" and port == expected else "FAIL", "Configured listen port",
                        f"configured={expected}, live={port}")
        self.probe("UDP/TCP listeners", ["ss", "-lntu"])
        self.expect("IPv4 forwarding", ["sysctl", "-n", "net.ipv4.ip_forward"], "1",
                    "Restore net.ipv4.ip_forward=1 in persistent sysctl settings and the running kernel; check UFW overrides.")
        if rc == 0:
            self.expect("wg0 IPv4 forwarding", ["sysctl", "-n", "net.ipv4.conf.wg0.forwarding"], "1",
                        "Review per-interface sysctl/UFW forwarding overrides for wg0.")
        self.probe("IPv6 forwarding (this VPN provides IPv4 Internet)", ["sysctl", "net.ipv6.conf.all.forwarding"], required=False)
        self.probe("Reverse path filtering", ["sysctl", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
                                               "net.ipv4.conf.wg0.rp_filter"], required=False)
        self.persistent_forwarding()
        self.probe("IPv4 routing policy", ["ip", "-4", "rule", "show"])
        self.probe("IPv4 routes (all tables)", ["ip", "-4", "route", "show", "table", "all"])
        rc, route = self.probe("Server route to Internet", ["ip", "-j", "-4", "route", "get", "1.1.1.1"])
        wan = None
        try:
            wan = json.loads(route)[0]["dev"] if rc == 0 else None
            if wan in {"wg0", "lo"}:
                self.report("FAIL", "Internet egress", f"Unexpected interface {wan}")
            elif wan:
                self.expect("WAN IPv4 forwarding", ["sysctl", "-n", f"net/ipv4/conf/{wan}/forwarding"], "1",
                            "Review per-interface forwarding on the WAN; return packets must also be forwarded.")
                self.probe("WAN reverse path filtering", ["sysctl", f"net/ipv4/conf/{wan}/rp_filter"], required=False)
        except (ValueError, KeyError, IndexError, TypeError):
            self.report("FAIL", "Internet egress", "Could not determine the WAN interface")
        self.firewall(hook, wan)
        if hook and hook[2] == 1053:
            self.expect("DNS filter service", ["systemctl", "is-active", "wireguard-dnsfilter"], "active",
                        "Inspect sudo journalctl -b -u wireguard-dnsfilter; also run make dnsfilter-status.")
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open("http://127.0.0.1:18080/health", timeout=5) as response:
                    healthy = response.status == 200 and response.read(64).strip() == b"OK"
            except OSError:
                healthy = False
            self.report("PASS" if healthy else "FAIL", "DNS filter local health", "OK" if healthy else "Unhealthy/unreachable",
                        "" if healthy else "Run make dnsfilter-status and inspect DNS filter logs.")
        self.probe("Server DNS lookup", ["getent", "ahostsv4", "example.com"], required=False)
        rc, handshakes, _ = self.run(["wg", "show", "wg0", "latest-handshakes"])
        try:
            stamps = [int(line.split()[1]) for line in handshakes.splitlines()] if rc == 0 else []
            recent = sum(0 < stamp and 0 <= time.time() - stamp <= 180 for stamp in stamps)
            self.report("PASS" if recent else "WARN", "Client handshakes",
                        f"{recent}/{len(stamps)} peers have a handshake within 180 seconds (peer keys omitted)",
                        "" if recent else "Connect a client and generate traffic; idle peers are not proof of failure. Check UDP/provider firewall if none connect.")
        except (ValueError, IndexError):
            self.report("WARN", "Client handshakes", "Unable to parse WireGuard handshake status")
        self.report("INFO", "Client Internet test",
                    "From a connected client, test a public IPv4 address, then a DNS lookup and a website. "
                    "Server DNS/health checks do not exercise client DNS redirection or forwarding.")
        print(f"\nResult: {self.failures} failed check(s). No configuration or services changed.")
        return 1 if self.failures else 0


if __name__ == "__main__":
    sys.exit(Diagnostics().check())

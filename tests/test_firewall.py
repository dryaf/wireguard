"""Exercise the rendered policy against packets and pre-existing public allows."""

from pathlib import Path
import re
import shlex
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]


class FirewallTests(unittest.TestCase):
    def policy(self, ipv6=False, ssh_port=2222, wireguard_port=51820):
        environment = Environment(loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined)
        before = "ufw6-before-input" if ipv6 else "ufw-before-input"
        variables = {"item": {"chain": before}, "ssh_port": ssh_port, "wireguard_port": wireguard_port}
        guard = environment.get_template("ufw-private-services.rules.j2").render(**variables)
        tasks = yaml.safe_load((ROOT / "tasks/wireguard_firewall_rules.yml").read_text())
        task = next(nested for task in tasks for nested in task.get("block", []) if "blockinfile" in nested)
        pattern = environment.from_string(task["blockinfile"]["insertbefore"]).render(**variables)
        original = (
            f"*filter\n:{before} - [0:0]\n"
            f"-A {before} -i lo -j ACCEPT\n"
            f"-A {before} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n"
        )
        insertion = re.search(pattern, original).start()
        config = original[:insertion] + guard + "\n" + original[insertion:]
        # Existing user rules even permit every port. The guard must precede them
        # and the normal established-connection shortcut in both address families.
        config += f"\n-A INPUT -j {before}\n-A INPUT -j ufw-user-input\n-A ufw-user-input -j ACCEPT\n"
        chains = {}
        for line in config.splitlines():
            tokens = shlex.split(line)
            if tokens and tokens[0] == "-A":
                chains.setdefault(tokens[1], []).append(dict(zip(tokens[2::2], tokens[3::2])))
        return chains

    def verdict(self, chains, interface, protocol, port, established=False, chain="INPUT"):
        for rule in chains.get(chain, []):
            if "-i" in rule and rule["-i"] != interface:
                continue
            if "-p" in rule and rule["-p"] != protocol:
                continue
            if "--dport" in rule and int(rule["--dport"]) != port:
                continue
            if "--ctstate" in rule and not established:
                continue
            target = rule["-j"]
            if target == "RETURN":
                return None
            if target in ("ACCEPT", "DROP"):
                return target
            verdict = self.verdict(chains, interface, protocol, port, established, target)
            if verdict is not None:
                return verdict
        return None

    def test_legacy_public_allows_cannot_expose_dns_or_web_on_either_family(self):
        for ipv6 in (False, True):
            policy = self.policy(ipv6)
            for interface in ("eth0", "ens5", "eth1"):
                for protocol, port in (("udp", 53), ("tcp", 53), ("tcp", 8080)):
                    for established in (False, True):
                        with self.subTest(ipv6=ipv6, interface=interface, protocol=protocol, port=port, established=established):
                            self.assertEqual(self.verdict(policy, interface, protocol, port, established), "DROP")

    def test_vpn_and_loopback_still_reach_private_services(self):
        for ipv6 in (False, True):
            policy = self.policy(ipv6)
            for interface in ("wg0", "lo"):
                for protocol, port in (("udp", 53), ("tcp", 53), ("tcp", 8080)):
                    self.assertEqual(self.verdict(policy, interface, protocol, port), "ACCEPT")

    def test_configured_ssh_and_wireguard_ports_are_exempt(self):
        for ipv6 in (False, True):
            for ssh_port in (22, 2222, 53, 8080):
                for wireguard_port in (51820, 53):
                    policy = self.policy(ipv6, ssh_port, wireguard_port)
                    self.assertEqual(self.verdict(policy, "eth0", "tcp", ssh_port), "ACCEPT")
                    self.assertEqual(self.verdict(policy, "eth0", "udp", wireguard_port), "ACCEPT")

    def test_unrelated_existing_allow_rules_still_apply(self):
        for ipv6 in (False, True):
            self.assertEqual(self.verdict(self.policy(ipv6), "eth0", "tcp", 443), "ACCEPT")


if __name__ == "__main__":
    unittest.main()

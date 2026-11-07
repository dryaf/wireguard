"""Automatic egress follows interface changes and fails before altering rules."""

from pathlib import Path
import shlex
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "files"), str(ROOT / "filter_plugins")]
from wireguard_firewall import HELPER, OperationError, WireGuardFirewall, managed_policy


class RoutingFirewallTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.route = '[{"dev":"eth0"}]'
        self.commands = []
        self.rules = {"filter": ["-A FORWARD -i other0 -j ACCEPT"], "nat": []}
        self.writes = []
        self.firewall = WireGuardFirewall(self.directory.name, self.runner)

    def runner(self, argv, stdin=None):
        self.commands.append(argv)
        if argv == ["ip", "-j", "-4", "route", "get", "1.1.1.1"]:
            if isinstance(self.route, Exception):
                raise self.route
            return self.route
        if argv[0] == "iptables-save":
            return "\n".join(self.rules[argv[-1]])
        if argv[0] == "iptables-restore":
            self.writes.append(stdin)
            table = None
            for line in stdin.splitlines():
                if line.startswith("*"):
                    table = line[1:]
                elif line.startswith("-A "):
                    self.rules[table].append(line)
                elif line.startswith("-D "):
                    rule = shlex.split(line.replace("-D ", "-A ", 1))
                    existing = next(value for value in self.rules[table] if shlex.split(value) == rule)
                    self.rules[table].remove(existing)
            return ""
        raise AssertionError(f"Unexpected command {argv}")

    def test_interface_change_reconciles_nat_without_editing_the_saved_hook(self):
        config = f"[Interface]\nPostUp = {HELPER} up --dns 1.1.1.1 --wan auto\nPostDown = {HELPER} down\n"
        policy = managed_policy(config)
        self.assertTrue(self.firewall.up(*policy))
        self.assertIn("-o eth0", "\n".join(self.rules["nat"]))
        self.assertFalse(self.firewall.up(*policy))
        self.route = '[{"dev":"ens3"}]'
        self.assertTrue(self.firewall.up(*policy))
        self.assertIn("-o ens3", "\n".join(self.rules["nat"]))
        self.assertNotIn("-o eth0", "\n".join(self.rules["nat"]))
        self.assertNotIn("-o auto", "\n".join(self.rules["nat"]))
        self.assertIn("-A FORWARD -i other0 -j ACCEPT", self.rules["filter"])
        self.assertFalse(self.firewall.up(*policy))
        # The same saved policy is also sufficient after shutdown and startup.
        self.assertTrue(self.firewall.down())
        self.assertTrue(self.firewall.up(*policy))
        self.assertIn("-o ens3", "\n".join(self.rules["nat"]))

    def test_invalid_or_missing_route_retains_existing_rules(self):
        self.firewall.up("1.1.1.1", "eth0")
        original = {table: list(rules) for table, rules in self.rules.items()}
        writes = len(self.writes)
        routes = ["invalid json", "[]", "{}", '[null]', '["ens3"]', '[{}]',
                  '[{"dev":"ens3"},{"dev":"ens4"}]', '[{"dev":"wg0"}]', '[{"dev":"lo"}]',
                  '[{"dev":"ens3;touch /tmp/injected"}]', '[{"type":"blackhole","dev":"ens3"}]',
                  OperationError("ip operation failed")]
        for route in routes:
            with self.subTest(route=route):
                self.route = route
                with self.assertRaisesRegex(OperationError, "Cannot determine the IPv4 WAN"):
                    # Also prove failure happens before optional DNS guards change.
                    self.firewall.up("10.99.0.1", "auto", 1053)
                self.assertEqual(self.rules, original)
                self.assertEqual(len(self.writes), writes)

    def test_explicit_legacy_interfaces_do_not_require_route_detection(self):
        self.route = OperationError("No route")
        config = f"PostUp = {HELPER} up --dns 1.1.1.1 --wan ens3\nPostDown = {HELPER} down\n"
        self.assertTrue(self.firewall.up(*managed_policy(config)))
        self.assertFalse(any(command[0] == "ip" for command in self.commands))
        self.assertIn("-o ens3", "\n".join(self.rules["nat"]))


if __name__ == "__main__":
    unittest.main()

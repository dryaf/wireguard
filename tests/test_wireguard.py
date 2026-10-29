"""Local regression tests; these never connect to or modify a VPN server."""

import json
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter_plugins"))

from wireguard import (
    FilterModule,
    wireguard_endpoint_host,
    wireguard_next_client_address,
    wireguard_peer_config,
    wireguard_peer_networks,
    wireguard_safe_client_name,
    wireguard_valid_client_name,
)


class ClientNameTests(unittest.TestCase):
    def test_valid_names(self):
        for name in ("alice", "phone-1", "Work_Laptop", "sal.mac", "a" * 15, "7"):
            with self.subTest(name=name):
                self.assertTrue(wireguard_valid_client_name(name))

    def test_rejects_paths_reserved_names_and_shell_input(self):
        for name in (
            "", "wg0", "WG0", "../sysctl", "/tmp/client", "alice laptop",
            "-x", "alice;id", "$(id)", "alice\n", "a" * 16, "älice", None, 7,
        ):
            with self.subTest(name=name):
                self.assertFalse(wireguard_valid_client_name(name))

    def test_safe_legacy_names_do_not_allow_paths_or_reserved_names(self):
        self.assertTrue(wireguard_safe_client_name("sal.mac"))
        self.assertTrue(wireguard_safe_client_name("alice-personal-phone"))
        for name in ("../sysctl", "wg0", "WG0", "alice;id", "alice\n", "a" * 251):
            self.assertFalse(wireguard_safe_client_name(name))

    def test_container_command_passes_input_verbatim_without_extra_variable_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            bindir = Path(directory)
            stub = bindir / "ansible-playbook"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "print(json.dumps({'name': os.environ['CLIENT_NAME'], 'args': sys.argv[1:]}))\n"
            )
            stub.chmod(0o700)
            (bindir / "ansible").symlink_to(stub)
            environment = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"])
            environment.pop("CLIENT_NAME", None)
            names = ("alice", "alice ansible_connection=local", "alice;echo INJECTED", "  alice  ")
            for operation in ("add", "remove", "qrcode"):
                for name in names:
                    with self.subTest(operation=operation, name=name):
                        result = subprocess.run(
                            [sys.executable, str(ROOT / "scripts/container_cli.py"), f"vpn-client-{operation}"],
                            cwd=ROOT, input=name + "\n", env=environment,
                            text=True, capture_output=True, check=True,
                        )
                        received = json.loads(result.stdout.removeprefix("Client name: "))
                        self.assertEqual(received["name"], name)
                        self.assertEqual(received["args"], [
                            "-i", "/run/wireguard/inventory.ini", f"wireguard_client_{operation}.yml",
                        ])


class PeerPreservationTests(unittest.TestCase):
    def setUp(self):
        environment = Environment(
            loader=FileSystemLoader(ROOT / "templates"),
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            trim_blocks=True,
        )
        environment.filters.update(FilterModule().filters())
        self.template = environment.get_template("wg0.conf.j2")
        self.variables = {
            "wireguard_address": "10.99.0.1/24",
            "wireguard_port": 51820,
            "server_priv_key_final": "DUMMY_PRIVATE_KEY",
            "ansible_facts": {"default_ipv4": {"interface": "eth0"}},
            "dns_server": "1.1.1.1",
        }

    def test_fresh_setup_has_no_peers(self):
        rendered = self.template.render(**self.variables)
        self.assertNotIn("[Peer]", rendered)
        self.assertEqual(wireguard_peer_config(rendered), "")

    def test_rerun_preserves_managed_and_manual_peers(self):
        peers = (
            "# BEGIN ANSIBLE MANAGED BLOCK FOR alice\n"
            "[Peer]\n# alice\nPublicKey = ALICE_PUBLIC_KEY\n"
            "AllowedIPs = 10.99.0.2/32\n"
            "# END ANSIBLE MANAGED BLOCK FOR alice\n\n"
            "# Manually configured router\n"
            "[Peer]\nPublicKey = ROUTER_PUBLIC_KEY\n"
            "AllowedIPs = 10.99.0.3/32, 192.168.50.0/24"
        )
        original = "[Interface]\nPrivateKey = OLD_DUMMY_KEY\n\n" + peers + "\n"
        rendered = self.template.render(
            **self.variables, wireguard_existing_peers=wireguard_peer_config(original)
        )
        self.assertIn(peers, rendered)
        self.assertNotIn("OLD_DUMMY_KEY", rendered)
        self.assertEqual(rendered.count("[Interface]"), 1)
        self.assertEqual(rendered.count("[Peer]"), 2)
        rerendered = self.template.render(
            **self.variables, wireguard_existing_peers=wireguard_peer_config(rendered)
        )
        self.assertEqual(rendered, rerendered)

    def test_first_unmanaged_peer_is_preserved(self):
        peers = "[Peer]\nPublicKey = PUBLIC_KEY\nAllowedIPs = 10.99.0.2/32"
        self.assertEqual(
            wireguard_peer_config("[Interface]\nPrivateKey = DUMMY\n" + peers),
            peers,
        )

    def test_wireguard_case_and_whitespace_variants_keep_peers_and_addresses(self):
        for header in ("[peer]", "[PEER]", "[ Peer ]", "[\tpEeR\t]"):
            for key in ("allowedips", "ALLOWEDIPS", "Allowed IPs"):
                with self.subTest(header=header, key=key):
                    peer = f"{header}\nPublicKey = PUBLIC_KEY\n{key} = 10.99.0.2 / 32\n"
                    config = "[Interface]\nPrivateKey = DUMMY\n" + peer
                    preserved = wireguard_peer_config(config)
                    rendered = self.template.render(**self.variables, wireguard_existing_peers=preserved)
                    self.assertIn("PUBLIC_KEY", rendered)
                    self.assertEqual(wireguard_peer_networks(rendered), ["10.99.0.2/32"])
                    self.assertEqual(wireguard_next_client_address(
                        "10.99.0.1/24", wireguard_peer_networks(rendered)
                    ), "10.99.0.3/32")


class ClientRoutingTests(unittest.TestCase):
    def test_ipv6_endpoints_are_bracketed_and_invalid_hosts_are_rejected(self):
        for host, expected in (("2001:db8::1", "[2001:db8::1]"), ("[2001:db8::1]", "[2001:db8::1]"), ("vpn.example.org", "vpn.example.org"), ("192.0.2.1", "192.0.2.1")):
            self.assertEqual(wireguard_endpoint_host(host), expected)
        for host in ("", "[example.org]", "host\nPostUp=id", "fe80::1%eth0;id", "$(id)"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                wireguard_endpoint_host(host)

    def test_generated_profile_routes_both_address_families_into_the_tunnel(self):
        environment = Environment(
            loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined,
        )
        environment.filters.update(FilterModule().filters())
        template = environment.get_template("client.conf.j2")
        config = template.render(
            client_address="10.99.0.2/32", client_private_key={"stdout": "DUMMY"},
            server_public_key={"stdout": "DUMMY"}, wireguard_gateway_ip="10.99.0.1",
            wireguard_port=51820, ansible_host="vpn.example.com",
            ansible_facts={"default_ipv4": {"address": "192.0.2.1"}},
        )
        allowed = next(line.split("=", 1)[1] for line in config.splitlines() if line.startswith("AllowedIPs"))
        routes = [ipaddress.ip_network(value.strip()) for value in allowed.split(",")]
        for destination in ("1.1.1.1", "192.0.2.10", "2001:db8::10", "fd00::1"):
            with self.subTest(destination=destination):
                address = ipaddress.ip_address(destination)
                self.assertTrue(any(address.version == route.version and address in route for route in routes))


class AddressAllocationTests(unittest.TestCase):
    def test_first_client_and_gateway_not_at_start_of_subnet(self):
        self.assertEqual(wireguard_next_client_address("10.99.0.1/24", []), "10.99.0.2/32")
        self.assertEqual(wireguard_next_client_address("10.99.0.100/24", []), "10.99.0.1/32")

    def test_reuses_a_gap_instead_of_overflowing_past_the_highest_client(self):
        self.assertEqual(wireguard_next_client_address("10.99.0.1/24", [
            "10.99.0.2/32", "10.99.0.4/32", "10.99.0.254/32",
        ]), "10.99.0.3/32")

    def test_exhaustion_and_reuse_in_a_non_default_subnet(self):
        used = []
        for host in range(2, 7):
            address = wireguard_next_client_address("192.168.10.1/29", used)
            self.assertEqual(address, f"192.168.10.{host}/32")
            used.append(address)
        with self.assertRaisesRegex(ValueError, "No free client address"):
            wireguard_next_client_address("192.168.10.1/29", used)
        used.remove("192.168.10.3/32")
        self.assertEqual(wireguard_next_client_address("192.168.10.1/29", used), "192.168.10.3/32")

    def test_default_pool_never_allocates_broadcast_or_an_address_outside_subnet(self):
        used = [f"10.99.0.{host}/32" for host in range(2, 254)]
        self.assertEqual(wireguard_next_client_address("10.99.0.1/24", used), "10.99.0.254/32")
        used.append("10.99.0.254/32")
        with self.assertRaisesRegex(ValueError, "No free client address"):
            wireguard_next_client_address("10.99.0.1/24", used)

    def test_reserves_aggregate_routes_and_ignores_other_networks(self):
        self.assertEqual(wireguard_next_client_address("10.99.0.1/24", [
            "10.99.0.0/25", "192.168.1.0/24", "2001:db8::/32",
        ]), "10.99.0.128/32")
        with self.assertRaisesRegex(ValueError, "No free client address"):
            wireguard_next_client_address("10.99.0.1/24", ["10.99.0.0/24"])

    def test_large_reserved_ranges_are_skipped(self):
        self.assertEqual(wireguard_next_client_address("10.0.0.1/8", ["10.0.0.0/9"]), "10.128.0.0/32")

    def test_invalid_pool_or_route_fails_closed(self):
        for address in ("2001:db8::1/64", "10.99.0.1/32", "10.99.0.0/24", "10.99.0.255/24"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                wireguard_next_client_address(address, [])
        with self.assertRaises(ValueError):
            wireguard_next_client_address("10.99.0.1/24", ["invalid route"])

    def test_peer_parser_handles_multiple_addresses_comments_and_ipv6(self):
        config = (
            "[Interface]\nPrivateKey = DUMMY_SECRET\nAddress = 10.99.0.1/24\n"
            "# AllowedIPs = 0.0.0.0/0\n"
            "[Peer]\nAllowedIPs = 10.99.0.2/32, 192.168.1.12/24 # office\n"
            "[Peer] # another client\nAllowedIPs = 10.99.0.3/32, 2001:db8::2/128\n"
        )
        self.assertEqual(wireguard_peer_networks(config), [
            "10.99.0.2/32", "192.168.1.0/24", "10.99.0.3/32", "2001:db8::2/128",
        ])

    def test_malformed_peer_routes_are_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            wireguard_peer_networks("[Peer]\nAllowedIPs = not-an-address\n")


if __name__ == "__main__":
    unittest.main()

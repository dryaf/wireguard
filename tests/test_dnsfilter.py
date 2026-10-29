"""Optional policy selection, safe hook parsing and preserved DNS defaults."""

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "files"), str(ROOT / "filter_plugins")]
import container_cli
from wireguard import FilterModule
from wireguard_firewall import HELPER, OperationError, managed_policy


def templates():
    environment = Environment(loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined)
    environment.filters.update(FilterModule().filters())
    return environment


class DNSFilterTests(unittest.TestCase):
    def test_prompt_accepts_yes_and_no_and_retries_typographical_errors(self):
        environment = dict(os.environ)
        environment.pop("DNSFILTER", None)
        with patch.dict(os.environ, environment, clear=True):
            for reply, expected in (("YES", True), ("n", False), ("", False)):
                with self.subTest(reply=reply), patch("builtins.input", return_value=reply):
                    self.assertEqual(container_cli.ask_dnsfilter(), expected)
            with patch("builtins.input", side_effect=["perhaps", "yes"]), patch("builtins.print"):
                self.assertTrue(container_cli.ask_dnsfilter())

    def test_invalid_noninteractive_choice_fails_before_ansible(self):
        with patch.dict(os.environ, DNSFILTER="maybe"), patch.object(container_cli, "run") as execute:
            with self.assertRaisesRegex(ValueError, "yes or no"):
                container_cli.main("vpn-server-setup", [])
            execute.assert_not_called()

    def test_enabled_choice_never_prompts_for_an_unfiltered_fallback(self):
        with patch.dict(os.environ, DNSFILTER="yes", DNS_SERVER="invalid and unused"), \
                patch("builtins.input", side_effect=AssertionError("Unexpected prompt")), \
                patch.object(container_cli, "run") as execute:
            container_cli.main("vpn-server-setup", [])
        args = execute.call_args.args
        self.assertEqual(json.loads(args[args.index("--extra-vars") + 1]), {"dnsfilter_enabled": True})

    def test_default_policy_blocks_malware_and_allows_adult_sites(self):
        config = yaml.safe_load(templates().get_template("dnsfilter.yml.j2").render(wireguard_address="10.44.8.1/22"))
        self.assertIs(config["filter_malware"], True)
        self.assertIs(config["filter_porn"], False)
        self.assertIs(config["filter_ads"], False)
        self.assertEqual(config["whitelist"], [])
        self.assertEqual(config["allowed_clients"], ["10.44.8.0/22"])
        self.assertEqual(config["metrics_addr"], "127.0.0.1:18080")

    def test_enable_switch_routes_all_client_dns_to_the_actual_gateway(self):
        values = dict(wireguard_address="10.44.8.1/22", wireguard_port=51820, server_priv_key_final="TEST_ONLY",
                      dns_server="9.9.9.9", ansible_default_ipv4={"interface": "eth0"})
        for enabled, expected in ((False, ("9.9.9.9", "eth0")), (True, ("10.44.8.1", "eth0", 1053))):
            config = templates().get_template("wg0.conf.j2").render(**values, dnsfilter_enabled=enabled)
            self.assertEqual(managed_policy(config), expected)

    def test_extra_hook_arguments_cannot_turn_into_shell_commands(self):
        for suffix in ("--dns-port 1053;id", "--dns-port 0", "--dns-port 65536", "--dns-port 1.5", "--extra 1053"):
            with self.subTest(suffix=suffix), self.assertRaises((ValueError, OperationError)):
                managed_policy(f"[Interface]\nPostUp = {HELPER} up --dns 10.99.0.1 --wan eth0 {suffix}\nPostDown = {HELPER} down\n")

    def test_service_only_stops_its_own_container_receipt(self):
        unit = templates().get_template("wireguard-dnsfilter.service.j2").render(dnsfilter_image_id="sha256:" + "a" * 64)
        self.assertIn("--read-only --user=65532:65532 --cap-drop=ALL", unit)
        self.assertIn("--security-opt=no-new-privileges", unit)
        self.assertIn("--pull=never", unit)
        self.assertNotIn("--privileged", unit)
        self.assertNotIn("--replace", unit)
        for line in unit.splitlines():
            if line.startswith(("ExecStop=", "ExecStopPost=")):
                self.assertIn("--cidfile=/run/wireguard-dnsfilter/container-id", line)


if __name__ == "__main__":
    unittest.main()

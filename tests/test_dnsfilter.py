"""Optional policy selection, safe hook parsing and preserved DNS defaults."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "files"), str(ROOT / "filter_plugins")]
import container_cli
from wireguard import FilterModule
from wireguard_firewall import HELPER, OperationError, managed_policy
from dnsfilter import update_policy


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
                      dns_server="9.9.9.9", ansible_facts={"default_ipv4": {"interface": "eth0"}})
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

    def test_policy_changes_preserve_unrelated_settings_and_supply_ads_resolver(self):
        config = yaml.safe_load(templates().get_template("dnsfilter.yml.j2").render(wireguard_address="10.44.8.1/22"))
        config.pop("resolver_anti_ads")  # Installations made before ad controls.
        config["whitelist"] = ["allowed.example"]
        for category in ("ads", "porn", "malware"):
            for enabled in (True, False):
                with self.subTest(category=category, enabled=enabled):
                    updated = update_policy(config, category, enabled)
                    self.assertIs(updated["filter_" + category], enabled)
                    for key, value in config.items():
                        if key != "filter_" + category:
                            self.assertEqual(updated[key], value)
                    if category == "ads" and enabled:
                        self.assertEqual(updated["resolver_anti_ads"]["url"], "https://dns.adguard-dns.com/dns-query")
                    self.assertNotIn("resolver_anti_ads", config)
        for category, enabled in (("arbitrary", True), ("ads", "yes"), ("malware", 1)):
            with self.assertRaises(ValueError):
                update_policy(config, category, enabled)
        with self.assertRaises(ValueError):
            update_policy(dict(config, filter_ads="false"), "ads", True)

    def test_setup_preserves_saved_flags_unless_explicitly_overridden(self):
        saved = dict(filter_malware=False, filter_ads=True, filter_porn=True)
        template = templates().get_template("dnsfilter.yml.j2")
        config = yaml.safe_load(template.render(wireguard_address="10.44.8.1/22", dnsfilter_saved_policy=saved))
        for key, expected in saved.items():
            self.assertIs(config[key], expected)
        config = yaml.safe_load(template.render(wireguard_address="10.44.8.1/22", dnsfilter_saved_policy=saved,
                                               dnsfilter_block_porn=False))
        self.assertIs(config["filter_porn"], False)
        self.assertIs(config["filter_ads"], True)

    def test_real_ansible_policy_updates_preserve_data_without_deprecation_warnings(self):
        # Plain Python dicts do not reproduce Ansible's lazy container wrappers.
        # Load saved YAML through slurp/set_fact, then execute the actual task.
        install = yaml.safe_load((ROOT / 'tasks/install_dnsfilter.yml').read_text())
        transaction = next(task['block'] for task in install if 'block' in task)
        prepare = next(task for task in transaction if task['name'] == 'Prepare the requested flag without changing other DNS settings')
        policy = yaml.safe_load(templates().get_template('dnsfilter.yml.j2').render(wireguard_address='10.44.8.1/22'))
        policy.pop('resolver_anti_ads')
        policy['whitelist'] = ['allowed.example', '{{ must_remain_literal }}']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'config.yml'
            source.write_text(yaml.safe_dump(policy))
            tasks = [
                {'ansible.builtin.slurp': {'src': str(source)}, 'register': 'saved'},
                {'ansible.builtin.set_fact': {'dnsfilter_saved_policy': '{{ saved.content | b64decode | from_yaml | dnsfilter_validate_policy }}'}},
            ]
            outputs = []
            for category in ('ads', 'porn', 'malware'):
                for enabled in (True, False):
                    result_file = root / f'{category}-{enabled}.json'
                    outputs.append((category, enabled, result_file))
                    tasks.extend([
                        dict(prepare, vars=dict(dnsfilter_update_only=True, dnsfilter_category=category, dnsfilter_value=enabled)),
                        {'ansible.builtin.copy': {
                            'dest': str(result_file), 'mode': '0600',
                            'content': "{{ {'before': dnsfilter_saved_policy, 'after': dnsfilter_candidate_policy} | to_json }}",
                        }},
                    ])
            playbook = root / 'test.yml'
            playbook.write_text(yaml.safe_dump([{
                'hosts': 'localhost', 'gather_facts': False,
                'vars': {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable},
                'tasks': tasks,
            }], sort_keys=False))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(playbook)],
                                    text=True, capture_output=True, timeout=60,
                                    env=dict(os.environ, ANSIBLE_FILTER_PLUGINS=str(ROOT / 'filter_plugins'),
                                             ANSIBLE_DEPRECATION_WARNINGS='True', ANSIBLE_NOCOLOR='1'))
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertNotIn('DEPRECATION WARNING', output)
            self.assertNotIn('PluginLoader with aliases', output)
            for category, enabled, result_file in outputs:
                with self.subTest(category=category, enabled=enabled):
                    data = json.loads(result_file.read_text())
                    self.assertEqual(data['before'], policy)
                    self.assertIs(data['after']['filter_' + category], enabled)
                    for key, value in policy.items():
                        if key != 'filter_' + category:
                            self.assertEqual(data['after'][key], value)
                    if category == 'ads' and enabled:
                        self.assertEqual(data['after']['resolver_anti_ads']['url'], 'https://dns.adguard-dns.com/dns-query')

    def test_all_category_commands_pass_boolean_data_to_the_management_playbook(self):
        for category in ("ads", "porn", "malware"):
            for action in ("enable", "disable"):
                with patch.object(container_cli, "run") as execute:
                    container_cli.main(f"dnsfilter-{action}-{category}", [])
                args = execute.call_args.args
                self.assertEqual(args[3], "wireguard_dnsfilter.yml")
                self.assertEqual(json.loads(args[args.index("--extra-vars") + 1]),
                                 {"dnsfilter_action": "update", "dnsfilter_category": category, "dnsfilter_value": action == "enable"})

    def test_dns_logs_include_podman_journal_scope_and_support_non_root_admins(self):
        for command, follow in (("dnsfilter-logs", False), ("dnsfilter-monitor", True)):
            with patch.object(container_cli, "servers", return_value=[("vpn", "192.0.2.1", 2222, {"ansible_user": "admin"})]), \
                    patch.object(container_cli.os, "execvp") as execute:
                container_cli.main(command, [])
            args = execute.call_args.args[1]
            self.assertIn("BatchMode=yes", args)
            self.assertTrue(args[-1].startswith("sudo -n -- journalctl"))
            self.assertIn("CONTAINER_NAME=wireguard-dnsfilter", args[-1])
            self.assertIn("_SYSTEMD_UNIT=wireguard-dnsfilter.service", args[-1])
            self.assertEqual("--follow" in args[-1], follow)


if __name__ == "__main__":
    unittest.main()

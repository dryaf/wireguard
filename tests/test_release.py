"""Release regressions exercised through the real, locked Ansible controller."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter_plugins"))
from wireguard import FilterModule


class ReleaseTests(unittest.TestCase):
    def test_inventory_alias_cannot_escape_the_export_directory(self):
        validate = FilterModule().filters()["wireguard_export_host"]
        for value in ("../outside", "x/../../other", "/tmp/secret", "a\\b", ".", "..", "a\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)
        self.assertEqual(validate("vpn.example.org"), "vpn.example.org")
        self.assertEqual(validate("2001:db8::1"), "2001:db8::1")

    def run_play(self, root, plays, inventory="fixture,", json_output=False):
        playbook = root / "probe.yml"
        playbook.write_text(yaml.safe_dump(plays))
        environment = dict(os.environ, ANSIBLE_FILTER_PLUGINS=str(ROOT / "filter_plugins"))
        if json_output:
            environment["ANSIBLE_STDOUT_CALLBACK"] = "ansible.posix.json"
        return subprocess.run(["ansible-playbook", "-i", str(inventory), str(playbook)],
                              cwd=ROOT, env=environment, text=True, capture_output=True)

    def test_direct_playbook_input_is_rejected_before_any_mutation(self):
        setup = yaml.safe_load((ROOT / "wireguard_server_setup.yml").read_text())[0]
        for key, value in (("dns_server", "1.1.1.1;touch /tmp/injected"), ("wireguard_mtu", "1280\nPostUp=id"), ("wireguard_port", "51820 ansible_connection=local")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker = root / "mutated"
                variables = dict(setup["vars"], ansible_connection="local", ansible_python_interpreter=sys.executable,
                                 ansible_facts={"distribution": "Debian", "service_mgr": "systemd", "default_ipv4": {"interface": "eth0"}})
                variables[key] = value
                first_task = dict(setup["tasks"][0])
                first_task["ansible.builtin.import_tasks"] = str(ROOT / first_task["ansible.builtin.import_tasks"])
                result = self.run_play(root, [{"hosts": "all", "gather_facts": False, "vars": variables, "tasks": [
                    first_task, {"ansible.builtin.copy": {"content": "mutation", "dest": str(marker)}},
                ]}])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(marker.exists())
                self.assertIn("Validate server settings", result.stdout)

    def test_completed_first_host_does_not_skip_other_hosts_polling_delay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.yml"
            inventory.write_text(yaml.safe_dump({"all": {"children": {"servers": {"hosts": {
                "a_done": {"wireguard_apply_result": {"ok": True}},
                "z_waiting": {"wireguard_apply_result": None},
            }}}}}))
            result = self.run_play(root, [{"hosts": "servers", "gather_facts": False, "vars": {
                "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                "wireguard_staging": {"path": str(root / "pending")},
            }, "tasks": [{"ansible.builtin.include_tasks": str(ROOT / "tasks/wait_for_wireguard_apply.yml"),
                          "loop": [0], "loop_control": {"loop_var": "wireguard_wait_attempt"}}]}], inventory, True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            tasks = json.loads(result.stdout)["plays"][0]["tasks"]
            delay = next(task for task in tasks if task["task"]["name"] == "Wait before checking again")
            self.assertTrue(delay["hosts"]["a_done"]["skipped"])
            self.assertGreaterEqual(delay["hosts"]["z_waiting"]["elapsed"], 5)

    def test_ipv6_profile_and_server_template_have_no_injection_path(self):
        environment = Environment(loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined)
        environment.filters.update(FilterModule().filters())
        config = environment.get_template("client.conf.j2").render(
            client_address="10.99.0.2/32", client_private_key={"stdout": "TEST_ONLY"},
            server_public_key={"stdout": "TEST_ONLY"}, wireguard_gateway_ip="10.99.0.1",
            wireguard_port=51820, ansible_host="2001:db8::1",
        )
        self.assertIn("Endpoint = [2001:db8::1]:51820", config)
        variables = dict(wireguard_address="10.99.0.1/24", wireguard_port=51820, server_priv_key_final="TEST_ONLY",
                         ansible_default_ipv4={"interface": "eth0"}, dns_server="1.1.1.1")
        for key, value in (("dns_server", "1.1.1.1;id"), ("ansible_default_ipv4", {"interface": "eth0;id"}),
                           ("ansible_default_ipv4", {"interface": "--help"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                environment.get_template("wg0.conf.j2").render(**dict(variables, **{key: value}))


if __name__ == "__main__":
    unittest.main()

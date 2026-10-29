"""AppArmor policy parsing and the real Ansible customization/rollback tasks."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def check_profile_syntax():
    """Compile without loading any policy into the host or container kernel."""
    with tempfile.TemporaryDirectory() as temporary:
        profile = Path(temporary) / "wg-quick"
        extension = (ROOT / "templates/wireguard-apparmor-local.j2").read_text()
        for name in ("wg-quick", "/usr/bin/wg-quick"):
            profile.write_text(
                "include <tunables/global>\n"
                f"profile {name} /usr/bin/wg-quick {{\n"
                "include <abstractions/base>\n" + extension + "\n}\n"
            )
            result = subprocess.run(["apparmor_parser", "--skip-kernel-load", "--skip-cache", str(profile)],
                                    text=True, capture_output=True, timeout=30)
            assert result.returncode == 0, result.stdout + result.stderr
    print("PASS: real AppArmor parser accepts both supported parent profile names (no kernel policy changes)")


class AppArmorDeploymentTests(unittest.TestCase):
    def fixture(self, root, existing=True, profile_name="wg-quick"):
        policy = root / "apparmor"
        (policy / "local").mkdir(parents=True)
        (policy / "disable").mkdir()
        (policy / profile_name).write_text(f"include if exists <local/{profile_name}>\n")
        local = policy / "local" / profile_name
        if existing:
            local.write_text("# Administrator customization\n/etc/hosts r,\n")
            local.chmod(0o600)
        (root / "templates").symlink_to(ROOT / "templates", target_is_directory=True)
        for source in ROOT.glob("tasks/configure_wireguard_apparmor*.yml"):
            # Only remap /etc and ownership for this non-root fixture. All
            # module behavior and rollback decisions come from the real tasks.
            tasks = yaml.safe_load(source.read_text().replace("/etc/apparmor.d", str(policy)))
            def remap(value):
                if isinstance(value, dict):
                    return {key: str(os.getuid()) if key == "owner" and item == "root" else
                            str(os.getgid()) if key == "group" and item == "root" else remap(item)
                            for key, item in value.items()}
                if isinstance(value, list):
                    return [remap(item) for item in value]
                return value
            (root / source.name).write_text(yaml.safe_dump(remap(tasks)))
        parser = root / "apparmor_parser"
        parser.write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, sys
root = pathlib.Path(__file__).parent
with (root / 'calls').open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
profile = pathlib.Path(sys.argv[-1])
local = profile.parent / 'local' / profile.name
managed = local.exists() and 'BEGIN WIREGUARD MANAGER FIREWALL' in local.read_text()
failure = os.environ.get('APPARMOR_TEST_FAILURE')
if '--names' in sys.argv:
    print('wg-quick' if profile.name == 'wg-quick' else '/usr/bin/wg-quick')
if managed and failure in sys.argv:
    print('Injected AppArmor failure', file=sys.stderr)
    sys.exit(1)
''')
        parser.chmod(0o700)
        probe = root / "aa-exec"
        probe.write_text(f"#!{sys.executable}\nimport os, sys\nassert '--immediate' in sys.argv\nsys.exit(1 if os.environ.get('APPARMOR_TEST_FAILURE') == 'probe' else 0)\n")
        probe.chmod(0o700)
        return local

    def run_play(self, root, failure="", enabled=True):
        playbook = root / "test.yml"
        playbook.write_text(yaml.safe_dump([{
            "hosts": "localhost", "gather_facts": False,
            "vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                     "ansible_facts": {"apparmor": {"status": "enabled" if enabled else "disabled"}}},
            "tasks": [{"ansible.builtin.import_tasks": str(root / "configure_wireguard_apparmor.yml")}],
        }]))
        return subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)], cwd=ROOT,
                              env=dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"],
                                       APPARMOR_TEST_FAILURE=failure, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json"),
                              text=True, capture_output=True, timeout=90)

    def test_install_is_idempotent_and_preserves_administrator_rules(self):
        for name in ("wg-quick", "usr.bin.wg-quick"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                local = self.fixture(root, profile_name=name)
                for attempt in range(2):
                    result = self.run_play(root)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    if attempt:
                        self.assertEqual(json.loads(result.stdout)["stats"]["localhost"]["changed"], 0)
                self.assertTrue(local.read_text().startswith("# Administrator customization\n/etc/hosts r,\n"))
                self.assertEqual(local.read_text().count("profile wireguard-firewall {"), 1)
                self.assertEqual(list(local.parent.iterdir()), [local])
                calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
                self.assertEqual([call[0] for call in calls], ["--names", "--skip-kernel-load", "--replace"] * 2)

    def test_rejected_policy_restores_files_and_never_loads_an_uncompiled_profile(self):
        for existing in (False, True):
            for failure in ("--skip-kernel-load", "--replace", "probe"):
                with self.subTest(existing=existing, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    local = self.fixture(root, existing=existing)
                    before = local.read_bytes() if existing else None
                    result = self.run_play(root, failure=failure)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("previous local policy was restored", result.stdout)
                    self.assertEqual(local.read_bytes() if local.exists() else None, before)
                    if existing:
                        self.assertEqual(local.stat().st_mode & 0o777, 0o600)
                    calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
                    self.assertEqual([call[0] for call in calls],
                                     ["--names", "--skip-kernel-load", "--replace"] if failure == "--skip-kernel-load"
                                     else ["--names", "--skip-kernel-load", "--replace", "--replace"])

    def test_disabled_absent_and_unsupported_profiles(self):
        for scenario in ("disabled", "absent", "apparmor-disabled", "unsupported"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                local = self.fixture(root)
                before = local.read_bytes()
                profile = local.parent.parent / "wg-quick"
                if scenario == "disabled":
                    (profile.parent / "disable/wg-quick").symlink_to(profile)
                elif scenario == "absent":
                    profile.unlink()
                elif scenario == "unsupported":
                    profile.write_text("# No local include\n")
                result = self.run_play(root, enabled=scenario != "apparmor-disabled")
                self.assertEqual(result.returncode == 0, scenario != "unsupported", result.stdout + result.stderr)
                self.assertEqual(local.read_bytes(), before)
                self.assertFalse((root / "calls").exists())


if __name__ == "__main__":
    if sys.argv[1:] == ["--compile"]:
        check_profile_syntax()
    else:
        unittest.main()

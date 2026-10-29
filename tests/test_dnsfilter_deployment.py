"""Real Ansible file transactions with simulated Podman/systemd and real validation."""

import json
import os
from pathlib import Path
import pwd
import grp
import subprocess
import sys
import tempfile

import yaml
from test_dnsfilter import ROOT, templates


PLUGIN = '''
import json
from pathlib import Path
import subprocess
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = dict(self._task.args)
        operation = args.pop('operation')
        path = Path(task_vars['fixture_state'])
        state = json.loads(path.read_text())
        config = Path(task_vars['fixture_config'])
        unit = Path(task_vars['fixture_unit'])
        receipt = Path(task_vars['fixture_receipt'])
        state['events'].append([operation, args])
        result = {'changed': False}
        if operation == 'facts':
            services = {}
            if unit.exists():
                services['wireguard-dnsfilter.service'] = {
                    'state': 'running' if state['running'] else 'stopped',
                    'status': 'enabled' if state['enabled'] else 'disabled',
                }
            elif state.get('foreign_service'):
                services['wireguard-dnsfilter.service'] = state['foreign_service']
            result['ansible_facts'] = {'services': services}
        elif operation == 'service':
            if args.get('name') and not unit.exists():
                return dict(failed=True, msg='Unit not found')
            if 'enabled' in args:
                state['enabled'] = args['enabled']
            action = args.get('state')
            if action == 'stopped':
                state['running'] = False
                receipt.unlink(missing_ok=True)
            elif action == 'restarted' or (action == 'started' and not state['running']):
                previous = config.read_text() == state['previous_config']
                if previous and state.get('fail_rollback') and state['starts']:
                    result.update(failed=True, msg='Injected rollback start failure')
                else:
                    state['starts'] += 1
                    state['running'] = True
                    state['healthy'] = previous or not state.get('fail_candidate')
                    receipt.parent.mkdir(parents=True, exist_ok=True)
                    receipt.write_text(f"{state['starts']:064x}")
            result['status'] = {
                'ActiveState': 'active' if state['running'] and state['healthy'] else 'failed',
                'SubState': 'running' if state['running'] and state['healthy'] else 'failed',
            }
        elif operation == 'command':
            argv = args['argv']
            rc, stdout, stderr = 0, '', ''
            if argv[:2] == ['podman', 'build']:
                target = next(value.split('=', 1)[1] for value in argv if value.startswith('--iidfile='))
                Path(target).write_text('sha256:' + 'b' * 64)
            elif argv[:2] == ['podman', 'run']:
                assert '--network=none' in argv and '--cap-drop=ALL' in argv
                mount = next(value for value in argv if value.startswith('--mount='))
                source = next(value[4:] for value in mount.split(',') if value.startswith('src='))
                checked = subprocess.run([task_vars['fixture_binary'], '-checkConfig', '-configFile', source], text=True, capture_output=True)
                rc, stdout, stderr = checked.returncode, checked.stdout, checked.stderr
            elif argv[:2] == ['podman', 'exec']:
                rc = 0 if state['healthy'] or state.get('foreign_dns') else 1
            elif argv[:2] == ['podman', 'ps']:
                stdout = 'c' * 64 if state.get('orphan') else ''
            elif argv[0] == 'ss':
                stdout = 'udp UNCONN 0 0 0.0.0.0:1053 0.0.0.0:*' if state.get('ports_in_use') else ''
            elif argv[0] == 'mkdir':
                created = subprocess.run(argv, text=True, capture_output=True)
                rc, stdout, stderr = created.returncode, created.stdout, created.stderr
            elif argv[-1] == 'unprotect-dns':
                stdout = '{"ok": true, "changed": true}'
            else:
                raise AssertionError('Unexpected fixture command: ' + repr(argv))
            result.update(rc=rc, stdout=stdout, stderr=stderr, failed=rc != 0)
        elif operation != 'packages':
            raise AssertionError('Unexpected fixture action: ' + operation)
        path.write_text(json.dumps(state))
        return result
'''


def run_tests(binary):
    scenarios = ("success", "invalid_config", "failed_readiness", "foreign_dns", "first_install_failure",
                 "failed_vpn", "failed_rollback", "orphan_container", "foreign_service",
                 "stale_service_failure", "ports_in_use", "failed_vpn_rollback", "busy_deployment")
    for scenario in scenarios:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "dnsfilter"
            directory.mkdir()
            config = directory / "config.yml"
            unit = root / "units/wireguard-dnsfilter.service"
            unit.parent.mkdir()
            receipt = root / "run/container-id"
            deployment_lock = root / "setup.lock"
            if scenario == "busy_deployment":
                deployment_lock.mkdir()
            previous = templates().get_template("dnsfilter.yml.j2").render(wireguard_address="10.99.0.1/24", dnsfilter_block_malware=False)
            config.write_text(previous)
            config.chmod(0o600)
            unit.write_text("# Managed by the WireGuard project\nprevious unit\n")
            previous_unit = unit.read_bytes()
            state_path = root / "state.json"
            state = dict(running=True, healthy=True, enabled=True, starts=0, previous_config=previous, events=[],
                         fail_candidate=scenario in {"failed_readiness", "foreign_dns", "first_install_failure", "failed_rollback", "orphan_container", "stale_service_failure"},
                         foreign_dns=scenario == "foreign_dns", fail_rollback=scenario in {"failed_rollback", "failed_vpn_rollback"},
                         orphan=scenario == "orphan_container", ports_in_use=scenario == "ports_in_use")
            if scenario in {"first_install_failure", "stale_service_failure", "ports_in_use", "foreign_service"}:
                config.unlink()
                unit.unlink()
                state.update(running=False, enabled=False)
            if scenario == "foreign_service":
                state.update(running=True, enabled=True, foreign_service={"state": "running", "status": "enabled"})
            elif scenario == "stale_service_failure":
                state["foreign_service"] = {"state": "stopped", "status": "not-found"}
            state_path.write_text(json.dumps(state))
            plugins = root / "plugins"
            plugins.mkdir()
            (plugins / "dnsfilter_fixture.py").write_text(PLUGIN)
            (root / "templates").mkdir()
            for name in ("dnsfilter.yml.j2", "wireguard-dnsfilter.service.j2"):
                (root / "templates" / name).write_text((ROOT / "templates" / name).read_text())
            if scenario == "invalid_config":
                (root / "templates/dnsfilter.yml.j2").write_text("listen_addr: 0.0.0.0:1053\nfilter_malware: true\n")
            (root / "Dockerfile").symlink_to(ROOT / "Dockerfile")
            tasks_dir = root / "tasks"
            tasks_dir.mkdir()
            username = pwd.getpwuid(os.getuid()).pw_name
            groupname = grp.getgrgid(os.getgid()).gr_name

            def adapt(value):
                if isinstance(value, str):
                    return (value.replace("/etc/wireguard-dnsfilter", str(directory))
                            .replace("/etc/systemd/system/wireguard-dnsfilter.service", str(unit))
                            .replace("/run/wireguard-dnsfilter/container-id", str(receipt))
                            .replace("/run/wireguard-dnsfilter-setup.lock", str(deployment_lock)))
                if isinstance(value, list):
                    return [adapt(item) for item in value]
                if not isinstance(value, dict):
                    return value
                result = {key: adapt(item) for key, item in value.items()}
                for module, operation in (("systemd_service", "service"), ("service_facts", "facts"), ("apt", "packages"), ("command", "command")):
                    key = "ansible.builtin." + module
                    if key in result:
                        result["dnsfilter_fixture"] = dict(result.pop(key) or {}, operation=operation)
                if result.get("owner") == "root":
                    result["owner"] = username
                if result.get("group") == "root":
                    result["group"] = groupname
                if "retries" in result:
                    result["retries"] = 0
                    result["delay"] = 0
                return result

            for name in ("install_dnsfilter.yml", "verify_dnsfilter.yml", "rollback_dnsfilter.yml"):
                data = yaml.safe_load((ROOT / "tasks" / name).read_text())
                (tasks_dir / name).write_text(yaml.safe_dump(adapt(data), sort_keys=False))
            main_play = yaml.safe_load((ROOT / "wireguard_server_setup.yml").read_text())[0]
            combined = next(task for task in main_play["tasks"] if "block" in task)
            combined = adapt(combined)
            combined["block"][0] = ({"ansible.builtin.fail": {"msg": "Injected VPN failure"}} if scenario in {"failed_vpn", "failed_vpn_rollback"}
                                    else {"ansible.builtin.debug": {"msg": "Fixture VPN apply succeeded"}})
            variables = dict(ansible_connection="local", ansible_python_interpreter=sys.executable,
                             dnsfilter_enabled=True, dnsfilter_block_malware=True, dnsfilter_block_porn=False,
                             wireguard_address="10.99.0.1/24", wireguard_setup_complete=False,
                             fixture_state=str(state_path), fixture_config=str(config), fixture_unit=str(unit),
                             fixture_receipt=str(receipt), fixture_binary=binary)
            playbook = root / "test.yml"
            playbook.write_text(yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "vars": variables,
                "tasks": [{"ansible.builtin.include_tasks": "tasks/install_dnsfilter.yml"}, combined]}], sort_keys=False))
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)], text=True, capture_output=True, timeout=90,
                                    env=dict(os.environ, ANSIBLE_ACTION_PLUGINS=str(plugins), ANSIBLE_FILTER_PLUGINS=str(ROOT / "filter_plugins")))
            output = result.stdout + result.stderr
            state = json.loads(state_path.read_text())
            assert (result.returncode == 0) == (scenario == "success"), output
            if scenario == "success":
                assert yaml.safe_load(config.read_text())["filter_malware"] is True
                assert state["running"] and state["healthy"]
            elif scenario in {"first_install_failure", "stale_service_failure", "ports_in_use"}:
                assert not config.exists() and not unit.exists(), output
                assert not state["running"] and not state["enabled"], output
            elif scenario == "foreign_service":
                assert not config.exists() and not unit.exists(), output
                assert state["running"] and state["enabled"], output
                assert not any(event[0] == "service" for event in state["events"]), output
            elif scenario == "orphan_container":
                assert not any(event[0] == "command" and event[1]["argv"][-1] == "unprotect-dns" for event in state["events"]), output
            else:
                assert config.read_text() == previous and unit.read_bytes() == previous_unit, output
                assert config.stat().st_mode & 0o777 == 0o600, output
                if scenario not in {"failed_rollback", "failed_vpn_rollback"}:
                    assert state["running"] and state["healthy"], output
            backups = list(directory.glob(".deploy-*/previous-config"))
            assert bool(backups) == (scenario in {"failed_rollback", "orphan_container", "failed_vpn_rollback"}), output
            assert deployment_lock.exists() == (bool(backups) or scenario == "busy_deployment"), output
            if backups:
                assert str(backups[0].parent) in output, output
            else:
                assert not list(directory.glob(".deploy-*")), output
            print(f"PASS: Ansible DNS deployment {scenario.replace('_', ' ')} (simulated runtime)")

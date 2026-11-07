"""Security boundaries for dependency installation and container command dispatch."""

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import container_cli
import dependency_lock


class SSHPreflightTests(unittest.TestCase):
    def test_preflight_requires_public_keys_and_checks_nonroot_sudo_without_passwords(self):
        endpoints = [("first", "192.0.2.1", 22, {"ansible_user": "root"}),
                     ("second", "192.0.2.2", 2222, {"ansible_user": "admin"})]
        with patch.object(container_cli, "servers", return_value=endpoints), patch.object(container_cli, "run") as command:
            container_cli.check_ssh()
        self.assertEqual(command.call_count, 2)
        for call in command.call_args_list:
            for setting in ("BatchMode=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                            "Compression=no", "ForwardAgent=no", "StrictHostKeyChecking=yes", "ConnectTimeout=15"):
                self.assertIn(setting, call.args)
        self.assertEqual(command.call_args_list[0].args[-2:], ("192.0.2.1", "true"))
        self.assertEqual(command.call_args_list[1].args[-2:], ("192.0.2.2", "sudo -n true"))

    def test_preflight_propagates_authentication_failure(self):
        with patch.object(container_cli, "servers", return_value=[("vpn", "192.0.2.1", 22, {"ansible_user": "root"})]), \
                patch.object(container_cli, "run", side_effect=subprocess.CalledProcessError(255, "ssh")):
            with self.assertRaises(subprocess.CalledProcessError):
                container_cli.check_ssh()


class DependencyLockTests(unittest.TestCase):
    def test_development_entrypoint_cannot_silently_scan_only_runtime_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("requirements.txt", "requirements-dev.txt"):
                (root / name).write_bytes((ROOT / name).read_bytes())
            with patch.object(dependency_lock, "ROOT", root):
                dependency_lock.check_entrypoints()
                (root / "requirements-dev.txt").write_text((root / "requirements.txt").read_text())
                with self.assertRaisesRegex(ValueError, "complete hashed lock"):
                    dependency_lock.check_entrypoints()

    def test_collection_file_aliases_are_allowed_but_cannot_redirect_extraction(self):
        for redirected in (False, True):
            with self.subTest(redirected=redirected), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "collection.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    data = b'{"collection_info": {"namespace":"test", "name":"fixture", "version":"1.0.0"}}'
                    member = tarfile.TarInfo("MANIFEST.json")
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
                    link = tarfile.TarInfo("aliases/manifest")
                    link.type, link.linkname = tarfile.SYMTYPE, "../MANIFEST.json"
                    output.addfile(link)
                    if redirected:
                        output.addfile(tarfile.TarInfo("aliases/manifest/outside"))
                if redirected:
                    with self.assertRaises(ValueError):
                        dependency_lock.collection_manifest(archive)
                else:
                    self.assertEqual(dependency_lock.collection_manifest(archive)["name"], "fixture")

    def test_collection_paths_links_and_duplicate_names_are_rejected_before_galaxy(self):
        cases = (("../outside", tarfile.REGTYPE, ""), ("/outside", tarfile.REGTYPE, ""),
                 ("link", tarfile.SYMTYPE, "../../outside"), ("link", tarfile.LNKTYPE, "MANIFEST.json"),
                 ("MANIFEST.json", tarfile.REGTYPE, ""))
        for name, kind, target in cases:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "collection.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    data = b'{"collection_info": {"namespace":"test", "name":"fixture", "version":"1.0.0"}}'
                    manifest = tarfile.TarInfo("MANIFEST.json")
                    manifest.size = len(data)
                    output.addfile(manifest, io.BytesIO(data))
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, target
                    output.addfile(entry)
                with self.assertRaises(ValueError):
                    dependency_lock.collection_manifest(archive)

    def test_pip_hash_mode_installs_verified_wheels_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "hash_probe-1.0-py3-none-any.whl"
            files = {
                "hash_probe.py": "VALUE = 1\n",
                "hash_probe-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: hash-probe\nVersion: 1.0\n",
                "hash_probe-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                "hash_probe-1.0.dist-info/RECORD": "",
            }
            files["hash_probe-1.0.dist-info/RECORD"] = "".join(f"{name},,\n" for name in files)
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            requirements = root / "requirements.lock"
            requirements.write_text(f"hash-probe==1.0 --hash=sha256:{dependency_lock.sha256(wheel)}\n")
            args = [sys.executable, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
                    "--no-index", "--no-deps", "--no-compile", "--find-links", str(root), "-r", str(requirements)]
            verified = subprocess.run([*args, "--target", str(root / "verified")], text=True, capture_output=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertTrue((root / "verified/hash_probe.py").is_file())
            with wheel.open("ab") as stream:
                stream.write(b"modified after locking")
            tampered = subprocess.run([*args, "--target", str(root / "tampered")], text=True, capture_output=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("DO NOT MATCH THE HASHES", tampered.stderr)
            self.assertFalse((root / "tampered/hash_probe.py").exists())

    def test_current_locks_are_complete_and_consistent(self):
        dependency_lock.check_locks()
        dependency_lock.check_collection_constraints(json.loads((ROOT / "locks/collections.lock.json").read_text()))

    def test_changed_input_or_partial_lock_update_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "locks").mkdir()
            for name in dependency_lock.SUMMED_FILES:
                (root / name).write_bytes((ROOT / name).read_bytes())
            (root / "locks/manifest.sha256").write_bytes((ROOT / "locks/manifest.sha256").read_bytes())
            with patch.object(dependency_lock, "ROOT", root), patch.object(dependency_lock, "LOCKS", root / "locks"):
                for name in ("requirements.in", "requirements.txt", "locks/requirements.lock"):
                    with self.subTest(file=name):
                        original = (root / name).read_bytes()
                        (root / name).write_bytes(original + b"# changed\n")
                        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                            dependency_lock.check_locks()
                        (root / name).write_bytes(original)

    def test_tampered_archive_is_rejected_before_unpacking_or_installing(self):
        class Opener:
            def open(self, *args, **kwargs):
                return io.BytesIO(b"tampered collection")

        with patch.object(dependency_lock.urllib.request, "build_opener", return_value=Opener()), \
                patch.object(dependency_lock, "collection_manifest") as unpack, \
                patch.object(dependency_lock.subprocess, "run") as install:
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                dependency_lock.install_collections()
            unpack.assert_not_called()
            install.assert_not_called()

    def test_missing_transitive_collection_is_rejected(self):
        data = json.loads((ROOT / "locks/collections.lock.json").read_text())
        data["collections"] = [entry for entry in data["collections"] if entry["name"] != "ansible.posix"]
        with self.assertRaisesRegex(ValueError, "Unpinned transitive collection"):
            dependency_lock.check_collection_lock(data)

    def test_incompatible_transitive_collection_is_rejected(self):
        data = json.loads((ROOT / "locks/collections.lock.json").read_text())
        hardening = next(entry for entry in data["collections"] if entry["name"] == "devsec.hardening")
        hardening["dependencies"]["ansible.posix"] = ">=999.0.0"
        with self.assertRaisesRegex(ValueError, "does not satisfy"):
            dependency_lock.check_collection_constraints(data)


class ContainerLauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.engine = self.root / "engine"
        self.engine.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "if args == ['--version']:\n"
            "    print('Docker version test')\n"
            "elif args[0] == 'build':\n"
            "    pathlib.Path(args[args.index('--iidfile') + 1]).write_text('sha256:' + 'a' * 64)\n"
            "elif args[0] == 'run':\n"
            "    print(json.dumps(args))\n"
            "else:\n"
            "    sys.exit(1)\n"
        )
        self.engine.chmod(0o700)
        self.environment = dict(os.environ, CONTAINER_ENGINE=str(self.engine),
                                WG_INVENTORY=str(self.root / "inventory.ini"),
                                WG_KNOWN_HOSTS=str(self.root / "known_hosts"),
                                WG_CLIENTS_DIR=str(self.root / "clients"))
        self.environment.pop("WG_SSH_AUTH_SOCK", None)

    def invoke(self, command, check=True):
        return subprocess.run(["make", "--no-print-directory", command], cwd=ROOT,
                              env=self.environment, text=True, capture_output=True, check=check)

    def test_tests_and_syntax_checks_have_no_network_credentials_or_host_mounts(self):
        self.environment.update(SSH_AUTH_SOCK="/sensitive/agent", CLIENT_NAME="private-name", DNS_SERVER="10.0.0.1")
        for command in ("test", "syntax-check", "deps-check", "dnsfilter-test"):
            with self.subTest(command=command):
                args = json.loads(self.invoke(command).stdout)
                self.assertIn("--network=none", args)
                self.assertIn("--read-only", args)
                self.assertIn("--cap-drop=ALL", args)
                self.assertIn("--security-opt=no-new-privileges", args)
                self.assertNotIn("--mount", args)
                self.assertNotIn("--env", args)
                self.assertEqual(args[-2:], ["sha256:" + "a" * 64, command])

    def test_audit_has_network_but_no_credentials_or_host_mounts(self):
        args = json.loads(self.invoke("audit").stdout)
        self.assertNotIn("--network=none", args)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--env", args)

    def test_deployment_only_mounts_selected_files_and_client_output(self):
        (self.root / "inventory.ini").write_text("[servers]\nvpn ansible_host=192.0.2.1\n")
        (self.root / "known_hosts").write_text("verified key fixture\n")
        with socket.socket(socket.AF_UNIX) as agent:
            agent_path = str(self.root / "agent")
            agent.bind(agent_path)
            self.environment.update(SSH_AUTH_SOCK=agent_path, CLIENT_NAME="alice;echo unexpected")
            args = json.loads(self.invoke("vpn-client-add").stdout)
        mounts = [args[index + 1] for index, arg in enumerate(args) if arg == "--mount"]
        self.assertEqual(mounts, [
            f"type=bind,src={self.root}/inventory.ini,dst=/run/wireguard/inventory.ini,readonly",
            f"type=bind,src={self.root}/known_hosts,dst=/run/wireguard/known_hosts,readonly",
            f"type=bind,src={self.root}/agent,dst=/run/wireguard/ssh-agent,readonly",
            f"type=bind,src={self.root}/clients,dst=/workspace/clients",
        ])
        self.assertIn("CLIENT_NAME", args)
        self.assertNotIn("alice;echo unexpected", args)

    def test_missing_engine_fails_without_host_fallback(self):
        self.environment["CONTAINER_ENGINE"] = str(self.root / "missing-engine")
        result = self.invoke("test", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Container engine not found", result.stderr)

    def test_dns_controls_mount_only_inventory_trust_and_agent(self):
        (self.root / 'inventory.ini').write_text('[servers]\nvpn ansible_host=192.0.2.1\n')
        (self.root / 'known_hosts').write_text('verified key fixture\n')
        with socket.socket(socket.AF_UNIX) as agent:
            agent_path = str(self.root / 'agent')
            agent.bind(agent_path)
            self.environment.update(SSH_AUTH_SOCK=agent_path, CLIENT_NAME='unrelated', DNSFILTER='no')
            commands = ('vpn-check', 'vpn-debug', 'dnsfilter-status', 'dnsfilter-logs', 'dnsfilter-monitor', *container_cli.DNSFILTER_CHANGES)
            for command in commands:
                with self.subTest(command=command):
                    args = json.loads(self.invoke(command).stdout)
                    mounts = [args[index + 1] for index, arg in enumerate(args) if arg == '--mount']
                    self.assertEqual(mounts, [
                        f'type=bind,src={self.root}/inventory.ini,dst=/run/wireguard/inventory.ini,readonly',
                        f'type=bind,src={self.root}/known_hosts,dst=/run/wireguard/known_hosts,readonly',
                        f'type=bind,src={self.root}/agent,dst=/run/wireguard/ssh-agent,readonly',
                    ])
                    self.assertNotIn('DNSFILTER', args)
                    self.assertNotIn('CLIENT_NAME', args)
                    self.assertEqual(args[-1], command)

    def test_native_fixture_is_rootless_isolated_and_cleaned_up_on_failure(self):
        log = self.root / "engine-calls.jsonl"
        self.engine.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            f"with pathlib.Path({str(log)!r}).open('a') as stream: stream.write(json.dumps(args) + '\\n')\n"
            "if args == ['--version']: print('Podman version test')\n"
            "elif args[0] == 'info': print('true')\n"
            "elif args[0] == 'build': pathlib.Path(args[args.index('--iidfile') + 1]).write_text('sha256:' + 'a' * 64)\n"
            "elif args[0] == 'run': pathlib.Path(args[args.index('--cidfile') + 1]).write_text('b' * 64)\n"
            "elif args[0] == 'exec': sys.exit(17)\n"
            "elif args[0] != 'rm': sys.exit(1)\n"
        )
        result = self.invoke("integration-test", check=False)
        self.assertNotEqual(result.returncode, 0)
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        run = next(args for args in calls if args[0] == "run")
        self.assertIn("--network=none", run)
        self.assertIn("--security-opt=no-new-privileges", run)
        self.assertIn("--cap-add=NET_ADMIN", run)
        self.assertNotIn("--privileged", run)
        self.assertNotIn("--mount", run)
        self.assertIn(["rm", "--force", "b" * 64], calls)
        self.assertFalse(Path(run[run.index("--cidfile") + 1]).parent.exists())

    def test_native_fixture_rejects_a_docker_engine(self):
        result = self.invoke("integration-test", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rootless Podman on Linux", result.stderr)

    def test_deployment_requires_verified_host_keys(self):
        (self.root / "inventory.ini").write_text("[servers]\nvpn\n")
        result = self.invoke("vpn-server-status", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Verified SSH host keys are required", result.stderr)


class ContainerCommandTests(unittest.TestCase):
    def test_vpn_check_and_debug_dispatch_to_the_same_read_only_playbook(self):
        for command in ("vpn-check", "vpn-debug"):
            with self.subTest(command=command), patch.object(container_cli, "run") as execute:
                container_cli.main(command, [])
                execute.assert_called_once_with("ansible-playbook", "-i", container_cli.INVENTORY, "server_debug_vpn.yml")

    def test_ansible_runs_filters_templates_and_local_delegation_as_non_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "wg0.conf"
            playbook = root / "probe.yml"
            playbook.write_text(yaml.safe_dump([{
                "hosts": "all", "gather_facts": False,
                "vars": {
                    "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                    "wireguard_address": "10.99.0.1/24", "wireguard_port": 51820,
                    "server_priv_key_final": "TEST_ONLY", "dns_server": "1.1.1.1",
                    "ansible_facts": {"default_ipv4": {"interface": "eth0", "address": "192.0.2.1"}},
                    "client_address": "10.99.0.2/32", "client_private_key": {"stdout": "TEST_ONLY"},
                    "server_public_key": {"stdout": "TEST_ONLY"}, "wireguard_gateway_ip": "10.99.0.1",
                },
                "tasks": [
                    {"ansible.builtin.assert": {"that": ["'phone' | wireguard_valid_client_name"]}},
                    {"ansible.builtin.command": {"argv": ["id", "-u"]}, "register": "identity", "changed_when": False},
                    {"ansible.builtin.assert": {"that": ["identity.stdout != '0'"]}},
                    {"ansible.builtin.template": {"src": str(ROOT / "templates/wg0.conf.j2"),
                                                  "dest": str(destination), "mode": "0600"},
                     "delegate_to": "localhost", "become": False},
                    {"ansible.builtin.template": {"src": str(ROOT / "templates/client.conf.j2"),
                                                  "dest": str(root / 'client.conf'), "mode": "0600"},
                     "delegate_to": "localhost", "become": False},
                ],
            }]))
            environment = dict(os.environ, ANSIBLE_FILTER_PLUGINS=str(ROOT / "filter_plugins"), ANSIBLE_INJECT_FACTS_AS_VARS='False')
            result = subprocess.run(["ansible-playbook", "-i", "fixture,", str(playbook)],
                                    cwd=ROOT, env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PrivateKey = TEST_ONLY", destination.read_text())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            # A delegated task gets localhost's connection variables. This
            # fixture verifies templating with injected fact aliases disabled.
            self.assertIn('Endpoint = localhost:51820', (root / 'client.conf').read_text())
            self.assertNotIn('INJECT_FACTS_AS_VARS', result.stderr)

    def test_dns_is_validated_before_ansible_runs(self):
        for value in ("1.1.1.1 ansible_connection=local", "$(id)", "1.1.1.1;id", "2001:db8::1"):
            with self.subTest(value=value), patch.dict(os.environ, DNS_SERVER=value, DNSFILTER="no"), patch.object(container_cli, "run") as execute:
                with self.assertRaises(ValueError):
                    container_cli.main("vpn-server-setup", [])
                execute.assert_not_called()

    def test_dns_is_transported_as_json_data(self):
        with patch.dict(os.environ, DNS_SERVER="9.9.9.9", DNSFILTER="no"), patch.object(container_cli, "run") as execute:
            container_cli.main("vpn-server-setup", [])
        args = execute.call_args.args
        self.assertEqual(json.loads(args[args.index("--extra-vars") + 1]), {"dns_server": "9.9.9.9", "dnsfilter_enabled": False})

    def test_inventory_input_cannot_inject_options_through_ipv6_scope(self):
        for host in ("192.0.2.1 ansible_connection=local", "fe80::1%eth0 ansible_connection=local", "host\n[all:vars]"):
            self.assertFalse(container_cli.valid_host(host))
        for host in ("vpn.example.org", "192.0.2.1", "2001:db8::1", "fe80::1%eth0"):
            self.assertTrue(container_cli.valid_host(host))

    def test_host_key_mismatch_does_not_change_existing_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text("previous trusted key\n")
            endpoints = [("vpn", "192.0.2.1", 2222, {})]
            scan = subprocess.CompletedProcess([], 0, stdout="[192.0.2.1]:2222 ssh-ed25519 KEY\n")
            fingerprint = subprocess.CompletedProcess([], 0, stdout=f"256 SHA256:{'A' * 43} host (ED25519)\n")
            with patch.object(container_cli, "KNOWN_HOSTS", known_hosts), \
                    patch.object(container_cli, "servers", return_value=endpoints), \
                    patch.object(container_cli, "run", side_effect=[scan, fingerprint]), \
                    patch("builtins.input", return_value="SHA256:" + "B" * 43):
                with self.assertRaisesRegex(ValueError, "Fingerprint mismatch"):
                    container_cli.update_known_hosts(trust=True)
            self.assertEqual(known_hosts.read_text(), "previous trusted key\n")

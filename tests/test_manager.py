"""Real file operations and failure recovery with simulated system commands."""

import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "files"), str(ROOT / "filter_plugins")]

from wireguard_manager import OperationError, WireGuardManager, atomic_write, sections
from wireguard_firewall import run_command
from wireguard import FilterModule


def public_key(private):
    return base64.b64encode(hashlib.sha256(private.strip().encode()).digest()).decode()


class FakeSystem:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.fail_sync = False
        self.calls = []
        self.live = set()
        self.active = True
        self.fail_start = False
        self.fail_rollback_stop = False
        self.ssh_connected = True
        self.generated_keys = 0
        self.delay_ip = 0
        self.interface_missing = False

    def __call__(self, argv, stdin=None):
        self.calls.append(argv)
        if argv == ["wg", "pubkey"]:
            return public_key(stdin) + "\n"
        if argv == ["wg", "genkey"]:
            self.generated_keys += 1
            return base64.b64encode(os.urandom(32)).decode() + "\n"
        if argv == ["ip", "-j", "-4", "address", "show", "dev", "wg0"]:
            time.sleep(self.delay_ip)
            return json.dumps([{"addr_info": [{"family": "inet", "local": "10.99.0.1", "prefixlen": 24}]}])
        if argv == ["wg", "show", "wg0", "listen-port"]:
            return "51821\n"
        if argv == ["wg", "show", "interfaces"]:
            return "wg0\n" if self.active and not self.interface_missing else ""
        if argv[:2] == ["wg-quick", "strip"]:
            return Path(argv[2]).read_text()
        if argv[:2] == ["wg", "syncconf"]:
            if self.fail_sync:
                raise OperationError("Simulated interruption before syncing")
            self.live = {
                key for part in sections(stdin) if part["section"] == "peer"
                for key in part["values"].get("publickey", [])
            }
            return ""
        if argv == ["systemctl", "stop", "wg-quick@wg0"]:
            if self.fail_rollback_stop and not self.fail_start:
                raise OperationError("Injected rollback stop failure")
            self.active = False
            self.ssh_connected = False
            return ""
        if argv in (["systemctl", "enable", "--now", "wg-quick@wg0"], ["systemctl", "start", "wg-quick@wg0"], ["systemctl", "restart", "wg-quick@wg0"]):
            if self.fail_start:
                self.fail_start = False
                raise OperationError("Simulated invalid new configuration")
            self.active = True
            if argv[1] == "restart":
                self.interface_missing = False
            self.ssh_connected = True
            return ""
        raise AssertionError(f"Unexpected command: {argv}")


class ManagerFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / "privatekey").write_text("SERVER_PRIVATE")
        self.client_key = public_key("CLIENT_PRIVATE")
        (self.directory / "wg0.conf").write_text(
            "[Interface]\nPrivateKey = SERVER_PRIVATE\n\n"
            "# BEGIN ANSIBLE MANAGED BLOCK FOR alice\n"
            f"[Peer]\nPublicKey = {self.client_key}\nAllowedIPs = 10.99.0.2/32\n"
            "# END ANSIBLE MANAGED BLOCK FOR alice\n"
        )
        (self.directory / "alice.conf").write_text(
            "[Interface]\nPrivateKey = CLIENT_PRIVATE\nAddress = 10.99.0.2/32\n"
            f"[Peer]\nPublicKey = {public_key('SERVER_PRIVATE')}\n"
        )
        (self.directory / "alice.zip").write_bytes(b"DUMMY_ARCHIVE")
        self.system = FakeSystem(self.directory)
        self.system.live = {self.client_key}
        self.manager = WireGuardManager(self.directory, self.system)

    def client_template(self):
        environment = Environment(loader=FileSystemLoader(ROOT / "templates"))
        environment.filters.update(FilterModule().filters())
        template = environment.get_template("client.conf.j2")
        text = template.render(
            client_address="$WG_CLIENT_ADDRESS", client_private_key={"stdout": "$WG_CLIENT_PRIVATE_KEY"},
            server_public_key={"stdout": "$WG_SERVER_PUBLIC_KEY"}, wireguard_gateway_ip="$WG_GATEWAY_IP",
            wireguard_port="$WG_SERVER_PORT", ansible_host="vpn.example.com",
            ansible_facts={"default_ipv4": {"address": "192.0.2.1"}},
        )
        path = self.directory / "client.template"
        path.write_text(text)
        return path


class RemovalTests(ManagerFixture):
    def test_missing_profile_does_not_hide_an_unmanaged_duplicate(self):
        (self.directory / "alice.conf").unlink()
        with self.manager.config_path.open("a") as stream:
            stream.write(f"\n[Peer]\nPublicKey = {self.client_key}\nAllowedIPs = 10.99.0.3/32\n")
        before = self.manager.config_path.read_text()
        with self.assertRaisesRegex(OperationError, "unmanaged"):
            self.manager.remove("alice")
        self.assertEqual(self.manager.config_path.read_text(), before)
        self.assertIn(self.client_key, self.system.live)

    def test_missing_profile_revocation_keeps_identity_until_sync_succeeds(self):
        (self.directory / "alice.conf").unlink()
        self.system.fail_sync = True
        with self.assertRaises(OperationError):
            self.manager.remove("alice")
        pending = self.directory / ".remove-alice.json"
        self.assertEqual(json.loads(pending.read_text())["public_key"], self.client_key)
        with self.assertRaisesRegex(OperationError, "removal is unfinished"):
            self.manager.add("alice", self.client_template())
        with self.manager.config_path.open("a") as stream:
            stream.write(f"\n[Peer]\nPublicKey = {self.client_key}\nAllowedIPs = 10.99.0.3/32\n")
        self.system.fail_sync = False
        with self.assertRaisesRegex(OperationError, "unmanaged"):
            self.manager.remove("alice")
        self.manager.config_path.write_text("[Interface]\nPrivateKey = SERVER_PRIVATE\n")
        self.manager.remove("alice")
        self.assertNotIn(self.client_key, self.system.live)
        self.assertFalse(pending.exists())

    def test_mismatched_profile_cannot_remove_another_clients_peer(self):
        before = self.manager.config_path.read_text().replace(self.client_key, public_key("BOB_PRIVATE"))
        self.manager.config_path.write_text(before)
        with self.assertRaisesRegex(OperationError, "disagree"):
            self.manager.remove("alice")
        self.assertEqual(self.manager.config_path.read_text(), before)

    def test_retry_revokes_live_peer_after_disk_update_was_interrupted(self):
        self.system.fail_sync = True
        with self.assertRaises(OperationError):
            self.manager.remove("alice")
        self.assertNotIn(self.client_key, (self.directory / "wg0.conf").read_text())
        self.assertIn(self.client_key, self.system.live)
        self.assertTrue((self.directory / "alice.conf").exists())
        self.system.fail_sync = False
        self.manager.remove("alice")
        self.assertNotIn(self.client_key, self.system.live)
        self.assertFalse((self.directory / "alice.conf").exists())
        self.assertFalse((self.directory / "alice.zip").exists())

    def test_retry_reconciles_when_client_files_are_already_absent(self):
        (self.directory / "wg0.conf").write_text("[Interface]\nPrivateKey = SERVER_PRIVATE\n")
        (self.directory / "alice.conf").unlink()
        (self.directory / "alice.zip").unlink()
        self.manager.remove("alice")
        self.assertEqual(self.system.live, set())
        self.manager.remove("alice")
        self.assertEqual(self.system.live, set())

    def test_offline_revocation_is_persistent(self):
        self.system.active = False
        self.manager.remove("alice")
        self.assertNotIn(self.client_key, (self.directory / "wg0.conf").read_text())

    def test_unmanaged_peer_does_not_report_a_successful_revocation(self):
        config = (self.directory / "wg0.conf").read_text()
        config = "\n".join(line for line in config.splitlines() if "ANSIBLE MANAGED" not in line)
        (self.directory / "wg0.conf").write_text(config)
        with self.assertRaisesRegex(OperationError, "unmanaged"):
            self.manager.remove("alice")
        self.assertTrue((self.directory / "alice.conf").exists())

    def test_legacy_client_names_can_be_revoked(self):
        for name in ("sal.mac", "alice-personal-phone"):
            with self.subTest(name=name):
                config = (self.directory / "wg0.conf").read_text()
                config = config.replace("FOR alice\n", f"FOR {name}\n")
                (self.directory / "wg0.conf").write_text(config)
                for extension in ("conf", "zip"):
                    (self.directory / f"alice.{extension}").rename(self.directory / f"{name}.{extension}")
                self.manager.remove(name)
                self.assertNotIn(self.client_key, self.system.live)
                self.assertFalse((self.directory / f"{name}.conf").exists())
                if name == "sal.mac":
                    self.setUp()


class ApplyTests(ManagerFixture):
    def test_unchanged_setup_repairs_missing_kernel_peers(self):
        candidate = self.stage()
        self.manager.apply(candidate)
        self.system.live.clear()
        self.assertFalse(self.manager.apply(candidate)["changed"])
        self.assertIn(self.client_key, self.system.live)

    def test_active_unit_with_missing_interface_is_restarted(self):
        candidate = self.stage()
        self.manager.apply(candidate)
        self.system.interface_missing = True
        self.manager.apply(candidate)
        self.assertFalse(self.system.interface_missing)
        self.assertIn(["systemctl", "restart", "wg-quick@wg0"], self.system.calls)

    def test_arbitrary_new_hooks_are_rejected_before_stopping_service(self):
        candidate = self.stage()
        with candidate.open("a") as stream:
            stream.write("PostUp = touch /tmp/should-not-exist\n")
        with self.assertRaisesRegex(OperationError, "managed firewall hooks"):
            self.manager.apply(candidate)
        self.assertFalse(any(call[0] == "systemctl" for call in self.system.calls))

    def test_missing_key_file_is_recovered_without_changing_server_identity(self):
        original = (self.directory / "privatekey").read_text()
        (self.directory / "privatekey").unlink()
        self.manager.initialize_key()
        self.assertEqual((self.directory / "privatekey").read_text(), original)
        self.assertEqual(self.system.generated_keys, 0)
        self.assertFalse(self.manager.initialize_key()["changed"])

    def test_fresh_key_initialization_does_not_rotate_on_retry(self):
        (self.directory / "privatekey").unlink()
        (self.directory / "wg0.conf").unlink()
        self.manager.initialize_key()
        self.manager.initialize_key()
        self.assertEqual(self.system.generated_keys, 1)

    def stage(self):
        stage = self.directory / "staged"
        stage.mkdir()
        candidate = stage / "wg0.conf"
        candidate.write_text("[Interface]\nPrivateKey = SERVER_PRIVATE\nMTU = 1280\n")
        return candidate

    def test_apply_finishes_without_any_controller_calls_after_stop(self):
        candidate = self.stage()
        self.manager.apply(candidate)
        self.assertTrue(self.system.active)
        self.assertTrue(self.system.ssh_connected)
        self.assertIn(self.client_key, (self.directory / "wg0.conf").read_text())
        self.system.calls.clear()
        self.assertFalse(self.manager.apply(candidate)["changed"])
        self.assertNotIn(["systemctl", "stop", "wg-quick@wg0"], self.system.calls)

    def test_failed_start_restores_previous_configuration_and_service(self):
        candidate = self.stage()
        original = (self.directory / "wg0.conf").read_text()
        self.system.fail_start = True
        with self.assertRaisesRegex(OperationError, "previous configuration was restored") as raised:
            self.manager.apply(candidate)
        self.assertIn("Simulated invalid new configuration", str(raised.exception))
        self.assertEqual((self.directory / "wg0.conf").read_text(), original)
        self.assertTrue(self.system.active)

    def test_peers_added_after_staging_are_preserved(self):
        candidate = self.stage()
        with (self.directory / "wg0.conf").open("a") as stream:
            stream.write("[peer]\nPublicKey = LATER_PEER\nallowedips = 10.99.0.3/32\n")
        self.manager.apply(candidate)
        self.assertIn("LATER_PEER", (self.directory / "wg0.conf").read_text())

    def test_rollback_attempts_restart_even_when_its_stop_command_fails(self):
        original = (self.directory / "wg0.conf").read_text()
        self.system.fail_start = True
        self.system.fail_rollback_stop = True
        with self.assertRaisesRegex(OperationError, "rollback failed"):
            self.manager.apply(self.stage())
        self.assertEqual((self.directory / "wg0.conf").read_text(), original)
        self.assertTrue(self.system.active)


class AdditionTests(ManagerFixture):
    def test_duplicate_key_cannot_be_exported_with_ambiguous_routes(self):
        with self.manager.config_path.open("a") as stream:
            stream.write(f"\n[Peer]\nPublicKey = {self.client_key}\nAllowedIPs = 192.168.0.0/24\n")
        with self.assertRaisesRegex(OperationError, "another peer entry"):
            self.manager.add("alice", self.client_template())

    def test_retry_after_archive_failure_keeps_key_and_active_peer(self):
        template = self.client_template()
        with patch.object(self.manager, "archive", side_effect=OSError("Disk full")):
            with self.assertRaises(OSError):
                self.manager.add("bob", template)
        profile = (self.directory / "bob.conf").read_text()
        key = self.manager.profile_keys(profile)[1]
        self.assertIn(key, self.system.live)
        self.manager.add("bob", template)
        self.assertEqual((self.directory / "bob.conf").read_text(), profile)
        self.assertEqual(self.system.generated_keys, 1)
        self.assertTrue((self.directory / "bob.zip").exists())
        self.assertEqual((self.directory / "bob.zip").stat().st_mode & 0o777, 0o600)
        self.assertIn("Endpoint = vpn.example.com:51821", profile)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", profile)

    def test_retry_after_sync_failure_activates_same_profile(self):
        template = self.client_template()
        self.system.fail_sync = True
        with self.assertRaises(OperationError):
            self.manager.add("bob", template)
        profile = (self.directory / "bob.conf").read_text()
        self.system.fail_sync = False
        self.manager.add("bob", template)
        self.assertEqual((self.directory / "bob.conf").read_text(), profile)
        self.assertIn(self.manager.profile_keys(profile)[1], self.system.live)
        self.assertEqual(self.system.generated_keys, 1)

    def test_interrupted_profile_is_reserved_before_its_peer_is_persisted(self):
        template = self.client_template()
        def interrupt_peer_write(path, content):
            if path == self.manager.config_path:
                raise OSError("Interrupted after persisting client profile")
            return atomic_write(path, content)
        with patch("wireguard_manager.atomic_write", side_effect=interrupt_peer_write):
            with self.assertRaises(OSError):
                self.manager.add("bob", template)
        saved_profile = (self.directory / "bob.conf").read_text()
        self.assertEqual(self.manager.add("charlie", template)["address"], "10.99.0.4/32")
        self.assertEqual(self.manager.add("bob", template)["address"], "10.99.0.3/32")
        self.assertEqual((self.directory / "bob.conf").read_text(), saved_profile)

    def test_missing_private_profile_does_not_rotate_an_existing_peer(self):
        (self.directory / "alice.conf").unlink()
        before = (self.directory / "wg0.conf").read_text()
        with self.assertRaisesRegex(OperationError, "private profile is missing"):
            self.manager.add("alice", self.client_template())
        self.assertEqual((self.directory / "wg0.conf").read_text(), before)
        self.assertEqual(self.system.generated_keys, 0)

    def test_existing_profile_can_be_exported_repeatedly(self):
        original = (self.directory / "alice.conf").read_text()
        self.manager.add("alice", self.client_template())
        self.manager.add("alice", self.client_template())
        self.assertEqual((self.directory / "alice.conf").read_text(), original)
        self.assertEqual(self.system.generated_keys, 0)

    def test_new_long_names_are_rejected_but_existing_long_names_can_resume(self):
        name = "alice-personal-phone"
        template = self.client_template()
        with self.assertRaises(OperationError):
            self.manager.add(name, template)
        (self.directory / "alice.conf").rename(self.directory / f"{name}.conf")
        config = (self.directory / "wg0.conf").read_text().replace("FOR alice\n", f"FOR {name}\n")
        (self.directory / "wg0.conf").write_text(config)
        self.manager.add(name, template)
        self.assertTrue((self.directory / f"{name}.zip").exists())


def concurrent_add(directory, template, name, start, output):
    try:
        system = FakeSystem(directory)
        system.delay_ip = 0.1
        start.wait(5)
        result = WireGuardManager(directory, system, lock_timeout=3).add(name, template)
        output.put((name, result["address"]))
    except Exception as error:
        output.put((name, "ERROR: " + str(error)))


def hold_server_lock(directory, ready):
    with WireGuardManager(directory, FakeSystem(directory)).locked():
        ready.set()
        time.sleep(10)


class ConcurrencyTests(ManagerFixture):
    def test_separate_processes_allocate_distinct_addresses_without_losing_peers(self):
        template = self.client_template()
        context = multiprocessing.get_context("fork")
        start = context.Event()
        output = context.Queue()
        jobs = [context.Process(target=concurrent_add, args=(str(self.directory), str(template), name, start, output)) for name in ("bob", "charlie")]
        for job in jobs:
            job.start()
            self.addCleanup(lambda process=job: process.terminate() if process.is_alive() else None)
        start.set()
        results = dict(output.get(timeout=5) for _ in jobs)
        for job in jobs:
            job.join(5)
            self.assertEqual(job.exitcode, 0)
        self.assertEqual(set(results.values()), {"10.99.0.3/32", "10.99.0.4/32"})
        config = (self.directory / "wg0.conf").read_text()
        self.assertEqual(len([part for part in sections(config) if part["section"] == "peer"]), 3)
        for name in ("alice", "bob", "charlie"):
            self.assertIn(f"# BEGIN ANSIBLE MANAGED BLOCK FOR {name}", config)

    def test_lock_times_out_and_is_released_when_its_process_dies(self):
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        holder = context.Process(target=hold_server_lock, args=(str(self.directory), ready))
        holder.start()
        self.addCleanup(lambda: holder.terminate() if holder.is_alive() else None)
        self.assertTrue(ready.wait(5))
        contender = WireGuardManager(self.directory, self.system, lock_timeout=0.1)
        with self.assertRaisesRegex(OperationError, "Another WireGuard operation"):
            with contender.locked():
                self.fail("Concurrent operation entered the locked region")
        holder.terminate()
        holder.join(5)
        with contender.locked():
            self.assertTrue((self.directory / ".management.lock").exists())


class CommandFailureTests(unittest.TestCase):
    def test_service_failure_gives_diagnostics_without_exposing_process_output(self):
        with patch("wireguard_firewall.subprocess.run") as process:
            process.return_value.returncode = 1
            process.return_value.stdout = "PRIVATE_KEY_IN_STDOUT"
            process.return_value.stderr = "PRIVATE_KEY_IN_STDERR"
            for command in (["systemctl", "enable", "--now", "wg-quick@wg0"], ["wg", "pubkey"]):
                with self.subTest(command=command), self.assertRaises(OperationError) as raised:
                    run_command(command, stdin="PRIVATE_KEY_IN_STDIN")
                message = str(raised.exception)
                self.assertNotIn("PRIVATE_KEY", message)
                if command[0] == "systemctl":
                    self.assertIn("journalctl -u wg-quick@wg0", message)
                    self.assertIn("AppArmor", message)


if __name__ == "__main__":
    unittest.main()

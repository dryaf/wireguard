"""Verify fingerprint input and trust updates with real OpenSSH key tooling."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import container_cli


class HostTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.keys, cls.fingerprints, cls.console_lines = [], [], []
        for name in ("previous", "current"):
            path = Path(cls.directory.name) / name
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "root@fixture with spaces",
                            "-f", str(path)], check=True, capture_output=True)
            cls.keys.append(" ".join(path.with_suffix(".pub").read_text().split()[:2]))
            line = subprocess.run(["ssh-keygen", "-E", "sha256", "-lf", str(path.with_suffix(".pub"))],
                                  check=True, text=True, capture_output=True).stdout.strip()
            cls.console_lines.append(line)
            cls.fingerprints.append(line.split()[1])

    def verify(self, known_hosts, answers, endpoints):
        execute = container_cli.run

        def scan_fixture(*args, **kwargs):
            if args[0] == "ssh-keyscan":
                host = args[-1]
                port = int(args[args.index("-p") + 1])
                line = f"{container_cli.known_host_name(host, port)} {self.keys[1]}\n"
                return subprocess.CompletedProcess(args, 0, stdout=line)
            # Fingerprint calculation and removal of old host entries use the
            # real client. Only network discovery is replaced by a local key.
            return execute(*args, **kwargs)

        with patch.object(container_cli, "KNOWN_HOSTS", known_hosts), \
                patch.object(container_cli, "servers", return_value=endpoints), \
                patch.object(container_cli, "run", side_effect=scan_fixture), \
                patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            container_cli.update_known_hosts(trust=True)

    def test_bare_and_full_console_fingerprints_update_only_the_selected_host(self):
        for port in (22, 2222):
            host = container_cli.known_host_name("192.0.2.1", port)
            for answer in (self.fingerprints[1], self.console_lines[1], f"  {self.console_lines[1]}  "):
                with self.subTest(port=port, answer=answer), tempfile.TemporaryDirectory() as directory:
                    known_hosts = Path(directory) / "known_hosts"
                    unrelated = f"192.0.2.2 {self.keys[0]}\n"
                    known_hosts.write_text(unrelated + f"{host} {self.keys[0]}\n")
                    self.verify(known_hosts, [answer], [("vpn", "192.0.2.1", port, {})])
                    lines = known_hosts.read_text().splitlines()
                    self.assertIn(unrelated.strip(), lines)
                    self.assertIn(f"{host} {self.keys[1]}", lines)
                    self.assertNotIn(f"{host} {self.keys[0]}", lines)

    def test_wrong_malformed_and_ambiguous_fingerprints_preserve_trust(self):
        answers = [self.fingerprints[0], self.console_lines[0], "", "SHA256:truncated",
                   self.console_lines[1].replace("(ED25519)", "(RSA)"),
                   f"{self.console_lines[0]}\n{self.console_lines[1]}",
                   f"{self.console_lines[0]} {self.console_lines[1]}",
                   f"256 {self.fingerprints[0]} comment-{self.fingerprints[1]} (ED25519)"]
        for answer in answers:
            with self.subTest(answer=answer), tempfile.TemporaryDirectory() as directory:
                known_hosts = Path(directory) / "known_hosts"
                original = f"192.0.2.1 {self.keys[0]}\n".encode()
                known_hosts.write_bytes(original)
                with self.assertRaises(ValueError):
                    self.verify(known_hosts, [answer], [("vpn", "192.0.2.1", 22, {})])
                self.assertEqual(known_hosts.read_bytes(), original)

    def test_later_host_mismatch_does_not_save_an_earlier_verified_host(self):
        with tempfile.TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            original = f"192.0.2.1 {self.keys[0]}\n192.0.2.2 {self.keys[0]}\n".encode()
            known_hosts.write_bytes(original)
            endpoints = [("first", "192.0.2.1", 22, {}), ("second", "192.0.2.2", 22, {})]
            with self.assertRaisesRegex(ValueError, "Fingerprint mismatch"):
                self.verify(known_hosts, [self.console_lines[1], self.console_lines[0]], endpoints)
            self.assertEqual(known_hosts.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

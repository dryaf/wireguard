"""The audit must retain findings, propagate failures and expose no credentials."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from osv_report import summarize, safe


class OSVTests(unittest.TestCase):
    def test_summary_does_not_hide_an_id_active_in_another_package(self):
        def entry(name, groups):
            return {"package": {"ecosystem": "Debian:13", "name": name, "version": "1"}, "groups": groups}
        data = {"results": [{"packages": [
            entry("first", [{"ids": ["CVE-test"], "experimental_analysis": {"CVE-test": {"unimportant": True}}}]),
            entry("second", [{"ids": ["CVE-test"]}]),
        ]}]}
        packages, active, filtered, rows = summarize(data)
        self.assertEqual(len(packages), 2)
        self.assertEqual(active, {"CVE-test"})
        self.assertEqual(filtered, set())
        self.assertEqual(len(rows), 1)

    def test_missing_report_and_terminal_escape_sequences_are_not_accepted_silently(self):
        with self.assertRaises(ValueError):
            summarize({})
        self.assertNotIn("\x1b", safe("package\x1b[2J\n"))
        self.assertNotIn("\n", safe("package\x1b[2J\n"))

    def test_scans_continue_after_findings_but_errors_never_report_success(self):
        for scanner_status, expected in ((0, 0), (1, 1), (128, 2)):
            with self.subTest(status=scanner_status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "scripts").mkdir()
                for name in ("container", "osv_scan.sh"):
                    shutil.copy2(ROOT / "scripts" / name, root / "scripts" / name)
                log = root / "calls.jsonl"
                engine = root / "engine"
                engine.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ['FIXTURE_LOG']).open('a') as out:
    out.write(json.dumps(args) + '\\n')
if args == ['--version']:
    print('Docker fixture')
elif args[0] == 'build':
    pathlib.Path(args[args.index('--iidfile') + 1]).write_text('sha256:' + 'a' * 64)
elif args[0] == 'save':
    pathlib.Path(args[args.index('--output') + 1]).write_text('inert image fixture')
elif args[0] == 'run':
    if 'scan' in args:
        print('{{"results": []}}')
        sys.exit(int(os.environ['FIXTURE_STATUS']))
else:
    sys.exit(1)
''')
                engine.chmod(0o700)
                environment = dict(os.environ, CONTAINER_ENGINE=str(engine), FIXTURE_LOG=str(log),
                                   FIXTURE_STATUS=str(scanner_status), SSH_AUTH_SOCK="/private/agent")
                result = subprocess.run([str(root / "scripts/container"), "osv-scan"], env=environment,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                scans = [call for call in calls if call[0] == "run" and "scan" in call]
                self.assertEqual(len(scans), 5)
                recursive = [call for call in scans if "--recursive" in call]
                self.assertEqual(len(recursive), 1)
                self.assertNotIn("--no-resolve", recursive[0])
                self.assertNotIn("--config", recursive[0])
                for call in scans:
                    self.assertIn("--read-only", call)
                    self.assertIn("--cap-drop=ALL", call)
                    self.assertIn("--security-opt=no-new-privileges", call)
                    self.assertNotIn("--env", call)
                    self.assertNotIn("/private/agent", " ".join(call))
                    self.assertNotIn("docker.sock", " ".join(call))
                    for index, value in enumerate(call):
                        if value == "--mount":
                            self.assertTrue(call[index + 1].endswith(",readonly"))
                            self.assertIn("dst=/artifacts/image.tar", call[index + 1])
                self.assertEqual(len(list((root / ".container/osv").glob("run.*/status.tsv"))), 1)


if __name__ == "__main__":
    unittest.main()

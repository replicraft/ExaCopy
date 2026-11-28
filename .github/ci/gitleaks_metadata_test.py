"""Synthetic controls for the scanner evidence boundary."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gitleaks_metadata import MAX_BYTES, locations, main


FINDING = {"rule": "sample-rule", "path_id": "b" * 64, "line": 7, "commit": "a" * 40}
MARKER = "text that must not be echoed"


class GitleaksMetadataTests(unittest.TestCase):
    def test_projected_fields_and_empty_report(self):
        self.assertEqual(locations(b"[\n]\n"), [])
        self.assertEqual(locations(json.dumps([FINDING]).encode()), [FINDING])
        template = Path(__file__).with_name("gitleaks-metadata.tmpl").read_text()
        self.assertEqual(
            template.splitlines(),
            [
                "[",
                "{{- range $index, $finding := . }}",
                "{{- if $index }},{{ end }}",
                '{{- dict "rule" $finding.RuleID "path_id" (sha256sum $finding.File) '
                '"line" $finding.StartLine "commit" $finding.Commit | mustToJson }}',
                "{{- end }}",
                "]",
            ],
        )

    def test_rejects_raw_fields_duplicate_keys_and_unsafe_locations(self):
        for changed in (
            FINDING | {"Match": MARKER},
            FINDING | {"Secret": MARKER},
            FINDING | {"path": ".github/test data.txt"},
            FINDING | {"File": ".github/test data.txt"},
            FINDING | {"path_id": ".github/test data.txt"},
            FINDING | {"path_id": "b" * 63},
            FINDING | {"path_id": "B" * 64},
            FINDING | {"path_id": "g" * 64},
            FINDING | {"line": True},
            FINDING | {"line": 0},
            FINDING | {"commit": "a" * 39},
            FINDING | {"rule": "invalid\nrule"},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                locations(json.dumps([changed]).encode())
        duplicate = json.dumps([FINDING]).replace('"line": 7', '"line": 7, "line": 8')
        with self.assertRaises(ValueError):
            locations(duplicate.encode())

    def test_failure_never_echoes_input_or_a_previous_valid_row(self):
        for payload in (
            json.dumps([FINDING, FINDING | {"Fragment": MARKER}]).encode(),
            json.dumps([FINDING | {"path_id": MARKER}]).encode(),
            MARKER.encode(),
            b" " * (MAX_BYTES + 1),
        ):
            with self.subTest(length=len(payload)):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(payload))):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(main(), 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "Gitleaks metadata report refused\n")

    def test_scanner_status_takes_precedence_and_stderr_is_discarded(self):
        script = Path(__file__).with_name("gitleaks-scan.sh").resolve()
        with TemporaryDirectory(prefix="exacopy-gitleaks-metadata-test-") as scratch:
            mock_scanner = Path(scratch) / "gitleaks"
            mock_scanner.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "sys.stdout.write(os.environ['EXACOPY_TEST_SCAN_REPORT'])\n"
                "sys.stderr.write('synthetic scanner diagnostic to discard')\n"
                "sys.exit(int(os.environ['EXACOPY_TEST_SCAN_STATUS']))\n",
                encoding="utf-8",
            )
            mock_scanner.chmod(0o700)
            for scanner_status, payload, status, expected in (
                (0, "[\n]\n", 0, []),
                (1, json.dumps([FINDING]), 1, [FINDING]),
                (0, MARKER, 1, None),
                (17, MARKER, 17, None),
            ):
                with self.subTest(scanner_status=scanner_status, expected=expected):
                    env = os.environ | {
                        "PATH": scratch + os.pathsep + os.environ["PATH"],
                        "EXACOPY_TEST_SCAN_REPORT": payload,
                        "EXACOPY_TEST_SCAN_STATUS": str(scanner_status),
                    }
                    result = subprocess.run(
                        ["bash", script], cwd=script.parents[2], env=env,
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, status)
                    self.assertNotIn("synthetic scanner diagnostic", result.stderr)
                    self.assertNotIn(MARKER, result.stdout + result.stderr)
                    if expected is None:
                        self.assertEqual(result.stdout, "")
                    else:
                        self.assertEqual(json.loads(result.stdout), expected)


if __name__ == "__main__":
    unittest.main()

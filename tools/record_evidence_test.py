import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import record_evidence


class RustGateFeatureTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "example", "features": {"protocol": [], "strict": []}}
        self.obligation = {"id": "P-123", "rust": {"test": "tests::round_trip"}}

    def test_omitted_or_empty_features_preserve_the_legacy_command(self):
        expected = [
            "cargo", "nextest", "run", "--locked", "-p", "example",
            "--no-tests", "fail", "--", "--exact", "tests::round_trip",
        ]
        for features in ({}, {"features": []}):
            link = self.obligation["rust"] | features
            with self.subTest(features=features):
                self.assertEqual(record_evidence.gate_command("example", None, "rust", link), expected)

    def test_explicit_features_are_selected_before_the_exact_test_filter(self):
        link = self.obligation["rust"]
        link["features"] = ["protocol", "strict"]
        self.assertEqual(record_evidence.rust_features(self.package, self.obligation), ["protocol", "strict"])
        self.assertEqual(record_evidence.gate_command("example", None, "rust", link), [
            "cargo", "nextest", "run", "--locked", "-p", "example",
            "--no-default-features", "--features", "protocol,strict",
            "--no-tests", "fail", "--", "--exact", "tests::round_trip",
        ])

    def test_feature_list_refuses_duplicates_unknown_names_and_other_shapes(self):
        link = self.obligation["rust"]
        for features, error in (
            (["protocol", "protocol"], "duplicate Rust gate"),
            (["unknown"], "undeclared Rust gate"),
            (["protocol,strict"], "undeclared Rust gate"),
            (["--all-features"], "undeclared Rust gate"),
            ("protocol", "list of names"),
            ([7], "list of names"),
        ):
            with self.subTest(features=features), self.assertRaisesRegex(ValueError, error):
                link["features"] = features
                record_evidence.rust_features(self.package, self.obligation)


class GateScratchTests(unittest.TestCase):
    def test_recorder_cleans_owned_gate_scratch_and_retains_raw_log(self):
        command = ["mock-kani-gate"]
        child_log = b"fixture output already sent to the recorder\n"
        for outcome, status, expected_log in (
            ("success", 0, child_log),
            ("timeout", 124, child_log + b"\nEvidence command timed out.\n"),
            ("startup", 127, b"\nCould not start evidence command: fixture startup error\n"),
        ):
            with self.subTest(outcome=outcome), TemporaryDirectory() as temporary:
                evidence = Path(temporary)
                log = evidence / "gate.log"
                inherited = evidence / "caller-scratch"
                inherited.mkdir()
                sentinel = inherited / "unrelated.log"
                sentinel.write_bytes(b"keep caller scratch\n")
                scratch_files = []

                process = mock.MagicMock()
                process.__enter__.return_value = process
                process.pid = 123
                process.wait.return_value = 0
                if outcome == "timeout":
                    process.wait.side_effect = [
                        subprocess.TimeoutExpired(command, record_evidence.RUN_TIMEOUT_SECONDS), -9,
                    ]

                def start(*args, env, stdout, **kwargs):
                    scratch = Path(env["EXACOPY_VERIFICATION_SCRATCH"])
                    self.assertNotEqual(scratch, inherited)
                    scratch_file = scratch / "endpoint-kani.log"
                    scratch_file.write_bytes(b"private fixture scratch\n")
                    scratch_files.append(scratch_file)
                    if outcome == "startup":
                        raise OSError("fixture startup error")
                    stdout.write(child_log)
                    return process

                with (
                    mock.patch.dict(os.environ, {"EXACOPY_VERIFICATION_SCRATCH": str(inherited)}),
                    mock.patch.object(record_evidence.subprocess, "Popen", side_effect=start),
                    mock.patch.object(record_evidence.os, "killpg", create=True),
                ):
                    _, _, observed, _ = record_evidence.run_gate(command, "kani", {}, log, evidence / "trace")

                self.assertEqual(observed, status)
                self.assertEqual(log.read_bytes(), expected_log)
                self.assertEqual(sentinel.read_bytes(), b"keep caller scratch\n")
                self.assertEqual(len(scratch_files), 1)
                self.assertFalse(scratch_files[0].exists())
                self.assertFalse(scratch_files[0].parent.exists())


if __name__ == "__main__":
    unittest.main()

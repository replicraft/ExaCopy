import json
import os
from datetime import datetime, timezone
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
        self.assertEqual(record_evidence.validate_gate_features(self.package, self.obligation, "rust"), ["protocol", "strict"])
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
                record_evidence.validate_gate_features(self.package, self.obligation, "rust")


class KaniGateFeatureTests(unittest.TestCase):
    def test_workspace_validation_rejects_undeclared_and_duplicate_kani_features(self):
        with TemporaryDirectory() as temporary:
            crate = Path(temporary)
            ledger = crate / "verification/obligations.toml"
            ledger.parent.mkdir()
            package = {
                "name": "example", "id": "example", "manifest_path": str(crate / "Cargo.toml"),
                "features": {"protocol": [], "strict": []},
            }
            metadata = {"workspace_members": ["example"], "packages": [package]}
            for features, error in (
                ('["protocol", "protocol"]', "duplicate Kani gate features"),
                ('["unknown"]', "undeclared Kani gate feature"),
                ('["protocol,strict"]', "undeclared Kani gate feature"),
                ('["--all-features"]', "undeclared Kani gate feature"),
                ('"protocol"', "Kani gate features must be a list of names"),
                ('[7]', "Kani gate features must be a list of names"),
            ):
                with self.subTest(features=features):
                    ledger.write_text(
                        '[[obligation]]\nid = "P-123"\ngates = ["kani"]\n'
                        f'kani = {{ features = {features} }}\n',
                        encoding="utf-8",
                    )
                    with (
                        mock.patch.object(record_evidence, "query", return_value=json.dumps(metadata)),
                        self.assertRaisesRegex(ValueError, error),
                    ):
                        list(record_evidence.workspace_obligations("kani"))

    def test_kani_record_acceptance_preserves_tool_status_and_artifact(self):
        exact = b"EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features strict,protocol\n"
        omitted = b"not enough arguments, inserting non-deterministic value"
        crossing = b"x" * (8192 - len(exact) - 20) + omitted + b"\n"
        for selected, fixture_log, exit_status, expected, explanation in (
            (True, b"legacy dispatcher output\n", 0, "fail", "exact requested feature profile"),
            (True, exact.replace(b"strict,protocol", b"protocol,strict"), 0,
             "fail", "exact requested feature profile"),
            (True, exact + exact, 0, "fail", "exact requested feature profile"),
            (True, exact + b"raw solver output\n", 0, "pass", None),
            (False, b"raw solver output\n", 0, "pass", None),
            (True, exact + crossing, 0, "fail", "omitted call argument"),
            (False, b"Warning: " + omitted + b"\n", 0, "fail", "omitted call argument"),
            (True, b"Warning: " + omitted + b"\n", 0, "fail", "omitted call argument"),
            (True, exact + crossing, 1, "fail", None),
            (True, exact + crossing, 124, "fail", None),
        ):
            with (
                self.subTest(selected=selected, exit_status=exit_status, expected=expected),
                TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                (root / "Cargo.lock").write_bytes(b"fixture lockfile\n")
                (root / "source.rs").write_bytes(b"fixture source\n")
                obligation = {
                    "id": "P-123", "source": "source.rs", "assumptions": [],
                    "kani": {
                        "unwind_bound": 1, "oracle": "Fixture oracle.",
                        "features": ["strict", "protocol"] if selected else [],
                    },
                }
                process = mock.MagicMock()
                process.__enter__.return_value = process
                process.wait.return_value = exit_status

                def start(*_args, stdout, **_kwargs):
                    stdout.write(fixture_log)
                    return process

                revision = "1234567890abcdef"
                with (
                    mock.patch.object(record_evidence, "ROOT", root),
                    mock.patch.object(record_evidence, "revision", return_value=(revision, False)),
                    mock.patch.object(record_evidence, "tool_version", return_value=("kani", "1.0")),
                    mock.patch.object(record_evidence.subprocess, "Popen", side_effect=start),
                ):
                    self.assertEqual(record_evidence.record_gate(
                        root, "example", root, obligation, "kani", revision, "x86_64-unknown-linux-gnu",
                    ), expected == "pass")
                report_file, = root.glob("*.json")
                retained_log, = root.glob("*.log")
                report = json.loads(report_file.read_text(encoding="utf-8"))
                self.assertEqual(report["outcome"], expected)
                self.assertEqual(report["exit_status"], exit_status)
                self.assertEqual(retained_log.read_bytes(), fixture_log)
                self.assertEqual(report["artifact_digest"], record_evidence.digest(retained_log))
                if explanation:
                    self.assertIn(explanation, report["review"]["justification"])

    def test_kani_omitted_argument_scan_propagates_read_failure(self):
        reader = mock.MagicMock()
        reader.__enter__.return_value = reader
        reader.read.side_effect = [b"x" * 8192, OSError("read failed after clean chunk")]
        with mock.patch.object(Path, "open", return_value=reader):
            with self.assertRaisesRegex(OSError, "read failed after clean chunk"):
                record_evidence.kani_log_issue(Path("solver.log"), [])
        self.assertEqual(reader.read.call_args_list, [mock.call(8192), mock.call(8192)])

    def test_kani_acknowledgement_uses_physical_lines_with_bounded_reads(self):
        acknowledgement = b"EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features strict"
        long_line = b"x" * ((len(acknowledgement) + 3) * 16_384)
        with TemporaryDirectory() as temporary:
            log = Path(temporary) / "solver.log"
            for data, matches in (
                (long_line + acknowledgement + b"\n", False),
                (long_line + acknowledgement + b"\n" + acknowledgement + b"\n", True),
                (acknowledgement + long_line + b"\n", False),
                (acknowledgement + b"\r\n", True),
                (acknowledgement + b"\r", False),
                (acknowledgement, True),
            ):
                with self.subTest(length=len(data), matches=matches):
                    log.write_bytes(data)
                    self.assertEqual(record_evidence.matches_kani_profile(log, ["strict"]), matches)

        reader = mock.MagicMock()
        reader.__enter__.return_value = reader
        reader.readline.side_effect = [acknowledgement + b"\n", OSError("read failed after acknowledgement")]
        with mock.patch.object(Path, "open", return_value=reader):
            self.assertFalse(record_evidence.matches_kani_profile(Path("solver.log"), ["strict"]))

    def test_record_binds_exact_kani_profile_and_preserves_other_gate_profiles(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_bytes(b"fixture lockfile\n")
            (root / "source.rs").write_bytes(b"fixture source\n")
            (root / "generated.lean").write_bytes(b"fixture extraction\n")
            runner = "verification/kani/check-clock.sh"
            (root / runner).parent.mkdir(parents=True)
            (root / runner).write_bytes(b"#!/bin/sh\nexit 0\n")
            output = root / "output"
            output.mkdir()
            source_revision = "1234567890abcdef"
            base = {"id": "P-123", "source": "source.rs", "assumptions": []}
            feature_args = ["--no-default-features", "--features", "strict,protocol"]
            for gate, link, features, command in (
                ("kani", {"unwind_bound": 1}, [], ["verification/check.sh", "kani"]),
                ("kani", {"unwind_bound": 1, "features": []}, [], ["verification/check.sh", "kani"]),
                ("kani", {"unwind_bound": 1, "features": ["strict", "protocol"]},
                 ["strict", "protocol"], ["verification/check.sh", "kani"] + feature_args),
                ("kani", {"unwind_bound": 1, "runner": runner}, [], [runner, "kani"]),
                ("kani", {"unwind_bound": 1, "runner": runner, "features": ["strict", "protocol"]},
                 ["strict", "protocol"], [runner, "kani"] + feature_args),
                ("lean", {"generated": "generated.lean"}, ["proof-extraction"],
                 ["verification/check.sh", "lean"]),
                ("rust", {"test": "exact"}, [],
                 ["cargo", "nextest", "run", "--locked", "-p", "example",
                  "--no-tests", "fail", "--", "--exact", "exact"]),
            ):
                with self.subTest(gate=gate, link=link):
                    def run_gate(observed, _gate, _link, log, _trace):
                        self.assertEqual(observed, command)
                        if gate == "kani" and features:
                            log.write_bytes(
                                b"EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features strict,protocol\n"
                            )
                        else:
                            log.write_bytes(b"fixture gate log\n")
                        return datetime(2026, 11, 28, tzinfo=timezone.utc), 1, 0, None

                    with (
                        mock.patch.object(record_evidence, "ROOT", root),
                        mock.patch.object(record_evidence, "revision", return_value=(source_revision, False)),
                        mock.patch.object(record_evidence, "tool_version", return_value=("fixture", "1.0")),
                        mock.patch.object(record_evidence, "run_gate", side_effect=run_gate),
                    ):
                        self.assertTrue(record_evidence.record_gate(
                            output, "example", root, base | {gate: {"oracle": "Fixture oracle.", **link}}, gate,
                            source_revision, "x86_64-unknown-linux-gnu",
                        ))
                    report_file, = output.glob("*.json")
                    report = json.loads(report_file.read_text(encoding="utf-8"))
                    self.assertEqual(report["profile"]["features"], features)
                    self.assertEqual(report["redacted_command"], command)
                    report_file.unlink()


class KaniRunnerPathTests(unittest.TestCase):
    def test_refuses_missing_outside_and_linked_runners_before_dispatch(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root / "model"
            verification = owner / "verification"
            verification.mkdir(parents=True)
            outside = root / "outside.sh"
            outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (owner / "outside.sh").write_bytes(outside.read_bytes())
            paths = [
                "outside.sh", "verification/../../outside.sh", outside.as_posix(),
                "verification/missing.sh", "verification", "verification/C:outside.sh",
                "verification/./missing.sh", "verification//missing.sh",
            ]
            if os.name == "posix":
                (verification / "linked.sh").symlink_to(outside)
                paths.append("verification/linked.sh")
            with mock.patch.object(record_evidence, "ROOT", root):
                for path in paths:
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        record_evidence.gate_command("example", owner, "kani", {"runner": path})
                self.assertEqual(record_evidence.gate_command("example", owner, "kani", {}),
                                 ["model/verification/check.sh", "kani"])


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

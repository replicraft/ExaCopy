#!/usr/bin/env python3
"""Portable negative controls for the native sync qualification oracles."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import fixture
import native
import qualify


class QualificationControls(unittest.TestCase):
    def test_exact_report_refuses_duplicate_labels_and_non_boolean_completeness(self):
        expected = {"scope_complete": True, "status": "matching_observations"}
        self.assertEqual(qualify.exact_report(qualify.canonical(expected), expected), expected)
        with self.assertRaisesRegex(ValueError, "differs"):
            qualify.exact_report(b'{"scope_complete":1,"status":"matching_observations"}', expected)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            qualify.exact_report(b'{"scope_complete":true,"status":"blocked","status":"matching_observations"}',
                                 expected)
        with self.assertRaisesRegex(ValueError, "differs"):
            qualify.exact_report(qualify.canonical(expected | {"baseline_created": True}), expected)

    def test_mount_admission_refuses_foreign_and_ambiguous_scopes(self):
        device = os.stat("/").st_dev
        prefix = b"108 31 %d:%d " % (os.major(device), os.minor(device))
        whole = prefix + b"/ /dev/shm rw - tmpfs tmpfs rw\n"
        self.assertEqual(qualify.mount_id(whole, device), "108")
        for rejected in (whole + whole, whole.replace(b"tmpfs", b"ext4"), whole.replace(b" / ", b" /subdir ")):
            with self.subTest(record=rejected), self.assertRaises(ValueError):
                qualify.mount_id(rejected, device)

    def test_test_inventory_rejects_omitted_ignored_and_duplicate_tests(self):
        tests = qualify.TEST_NAMES["platform"]
        lines = [f"test {name} ... ok" for name in tests]
        summary = f"test result: ok. {len(tests)} passed; 0 failed; 0 ignored;"
        qualify.verify_test_log("platform", "\n".join(lines + [summary]))
        for changed in (lines[:-1], [lines[0], *lines], [*lines[:-1], lines[-1].replace("ok", "ignored")]):
            with self.subTest(lines=changed), self.assertRaisesRegex(ValueError, "every exact"):
                qualify.verify_test_log("platform", "\n".join(changed + [summary]))
        with self.assertRaisesRegex(ValueError, "summary"):
            qualify.verify_test_log("platform", "\n".join(lines))

    def test_fingerprint_detects_content_metadata_and_namespace_writes(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            root = Path(name)
            item = root / "item"
            qualify.write_file(item, b"one")
            base = qualify.fingerprint(root)
            qualify.fingerprint(root)
            self.assertEqual(qualify.fingerprint(root), base, "reading alone changed the fingerprint")
            item.write_bytes(b"two")
            modified = qualify.fingerprint(root)
            self.assertNotEqual(modified, base)
            item.chmod(0o400)
            self.assertNotEqual(qualify.fingerprint(root), modified)
            item.unlink()
            item.symlink_to("missing")
            self.assertNotEqual(qualify.fingerprint(root), base)

    def test_report_gate_checks_fingerprint_even_on_child_timeout(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            root = Path(name)
            record = {"status": "fail"}

            def timed_out(*args, **kwargs):
                (root / "unexpected").touch()
                raise qualify.subprocess.TimeoutExpired(args[0], 1)

            # Linux raw-name behavior is exercised only by the required native lane.
            with patch.multiple(qualify, LEFT=b"left", RIGHT=b"right", SUBJECT=b"subject"), (
                patch.object(qualify.subprocess, "run", side_effect=timed_out)
            ):
                with self.assertRaisesRegex(ValueError, "changed owned fixture"):
                    qualify.run_case("both_absent", root, "preview", "oracle", "1", record)
            self.assertNotEqual(record["before_sha256"], record["after_sha256"])
            self.assertEqual(record["status"], "fail")


    def test_manifest_binding_refuses_drift_in_either_case_kind(self):
        source = Path(fixture.__file__).with_name("fixture.toml").read_text(encoding="utf-8")
        registration = f'schema_version = 1\n[native_fixtures]\nexacopy-cli = ["{fixture.FIXTURE}"]\n'
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            directory = Path(name).resolve()
            manifest = directory / "fixture.toml"
            owners = directory / "owners.toml"
            manifest.write_text(source, encoding="utf-8")
            owners.write_text(registration, encoding="utf-8")
            bound = fixture.bind_fixture(manifest, owners)
            self.assertEqual(bound["profile"], fixture.PROFILE)
            self.assertEqual(bound["target"], fixture.TARGET)
            self.assertEqual(bound["fixture_manifest_sha256"], hashlib.sha256(source.encode()).hexdigest())
            self.assertEqual(bound["native_owners_sha256"], hashlib.sha256(registration.encode()).hexdigest())
            mutations = (
                source.replace('selector = "equal"', 'selector = "equal_missing"'),
                source.replace('kind = "command"', 'kind = "rust-unit"', 1),
                source.replace('ignored = false', 'ignored = true', 1),
                source.replace('owner = "exacopy-platform"', 'owner = "exacopy-cli"', 1),
                source.replace(f'profile = "{fixture.PROFILE}"', 'profile = "linux-unrelated"'),
                source.replace(f'target = "{fixture.TARGET}"', 'target = "aarch64-unknown-linux-gnu"'),
            )
            for changed in mutations:
                with self.subTest(changed=changed[:100]):
                    manifest.write_text(changed, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "disagrees"):
                        fixture.bind_fixture(manifest, owners)
            manifest.write_text(source, encoding="utf-8")
            owners.write_text(registration.replace("exacopy-cli", "exacopy-platform"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not registered"):
                fixture.bind_fixture(manifest, owners)
            owners.write_text(registration.replace(f'["{fixture.FIXTURE}"]', f'["{fixture.FIXTURE}", "{fixture.FIXTURE}"]'), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not registered"):
                fixture.bind_fixture(manifest, owners)

    def test_listing_requires_exact_native_selector_inventory(self):
        names = qualify.TEST_NAMES["transfer"]
        good = f"{names[0]}: test\n1 test, 0 benchmarks\n"
        native.verify_listing(good, names)
        for report in ("0 tests", good + good, good.replace(": test", ": benchmark")):
            with self.subTest(report=report), self.assertRaisesRegex(ValueError, "exact manifest"):
                native.verify_listing(report, names)

    def test_selected_executable_rejects_substitutions_and_wrong_cargo_kind(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            root = Path(name).resolve()
            target = root / "target"
            target.mkdir()
            trusted = target / "test-binary"
            trusted.touch(mode=0o700)
            event = {"reason": "compiler-artifact", "target": {"name": "exacopy_platform", "kind": ["lib"]},
                     "profile": {"test": True}, "executable": str(trusted)}
            as_json = json.dumps(event)
            self.assertEqual(native.selected_executable(as_json, target, "exacopy_platform", "lib"), trusted)
            with self.assertRaisesRegex(ValueError, "one built"):
                native.selected_executable(as_json + "\n" + as_json, target, "exacopy_platform", "lib")
            with self.assertRaisesRegex(ValueError, "one built"):
                native.selected_executable(as_json, target, "exacopy_platform", "bin")
            outside = root / "other"
            outside.touch(mode=0o700)
            alias = target / "alias"
            alias.symlink_to(outside)
            for path in (outside, alias):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "custody"):
                    native.selected_executable(
                        json.dumps(event | {"executable": str(path)}), target, "exacopy_platform", "lib",
                    )

    def test_cargo_build_layout_keeps_libtest_binary_in_target_custody(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            work = Path(name).resolve()
            with patch.dict(os.environ, {"CARGO_BUILD_BUILD_DIR": str(work / "foreign")}, clear=True):
                env = native.private_build_environment(work)
            target = Path(env["CARGO_TARGET_DIR"]) / fixture.TARGET
            artifact = Path(env["CARGO_BUILD_BUILD_DIR"]) / fixture.TARGET / "debug/deps/libtest"
            artifact.parent.mkdir(parents=True)
            artifact.touch(mode=0o700)
            event = {"reason": "compiler-artifact", "target": {"name": "exacopy_platform", "kind": ["lib"]},
                     "profile": {"test": True}, "executable": str(artifact)}
            selected = native.selected_executable(json.dumps(event), target, "exacopy_platform", "lib")
            self.assertEqual(selected, artifact)

            substituted = work / "foreign" / fixture.TARGET / "debug/deps/libtest"
            substituted.parent.mkdir(parents=True)
            substituted.touch(mode=0o700)
            event["executable"] = str(substituted)
            with self.assertRaisesRegex(ValueError, "custody"):
                native.selected_executable(json.dumps(event), target, "exacopy_platform", "lib")

    def test_blocked_native_profile_records_all_unexecuted_cases(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-sync-controls-") as name:
            evidence = Path(name) / "evidence"
            argv = ["qualify.py", "--evidence", str(evidence), "--revision", "a" * 40]
            with patch.object(sys, "argv", argv), patch.object(qualify, "bind_fixture", return_value={
                "fixture_id": "linux-sync-preview", "target": fixture.TARGET, "profile": fixture.PROFILE,
            }), patch.object(qualify.platform, "system", return_value="Darwin"), (
                patch.object(qualify, "build_cli")
            ) as build:
                self.assertEqual(qualify.main(), qualify.BLOCKED_EXIT)
                build.assert_not_called()
            report = json.loads((evidence / "result.json").read_text())
            self.assertEqual(report["outcome"], "blocked")
            self.assertEqual(report["native_tests"]["platform"], {"status": "not_run", "passed": []})
            self.assertEqual(report["native_tests"]["transfer"], {"status": "not_run", "passed": []})
            self.assertEqual(report["preview"], {"status": "not_run", "cases": [], "fixture_removed": None})
            self.assertEqual(report["ext4_casefold"]["status"], "not_run")


if __name__ == "__main__":
    unittest.main()

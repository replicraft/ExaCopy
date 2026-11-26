"""Portable controls for the native qualification runner, without mounts or builds."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run


def outcome(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def successful_test(name):
    return f"running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;"


class RunnerControls(unittest.TestCase):
    def test_manifest_binds_exact_profile_and_complete_selector_inventory(self):
        raw = Path(run.__file__).with_name("fixture.toml").read_text()
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "fixture.toml"
            manifest.write_text(raw)
            binding = run.fixture_binding(manifest)
            self.assertEqual(binding["fixture_id"], "linux-protected-slot-observation")
            self.assertEqual(binding["fixture_manifest_sha256"], run.sha256(manifest))
            changes = (
                raw.replace('target = "x86_64-unknown-linux-gnu"', 'target = "other"'),
                raw.replace('profile = "linux-unprivileged-same-device-bind-v1"', 'profile = "other"'),
                raw.replace('rust_toolchain = "1.100.0"', 'rust_toolchain = "1.99.0"'),
                raw.replace('result = "result.json"', 'result = "other.json"'),
                raw.replace("schema_version = 1", "schema_version = true"),
                raw.replace("ignored = false", "ignored = true", 1),
                raw.replace("ignored = false", "ignored = 0", 1),
                raw.replace(run.ORDINARY[0], run.ORDINARY[1]),
                raw.rsplit("[[case]]", 1)[0],
                raw + raw[raw.rindex("[[case]]"):],
                raw + '\n[unknown]\nextra = true\n',
            )
            for changed in changes:
                with self.subTest(changed=changed):
                    self.assertNotEqual(raw, changed)
                    manifest.write_text(changed)
                    with self.assertRaises(RuntimeError):
                        run.fixture_binding(manifest)

    def test_requires_exact_inventory_with_unique_names(self):
        required = (*run.ORDINARY, run.MOUNT_TEST)
        valid = "\n".join(f"{name}: test" for name in required)
        run.check_listing(valid, required)
        for invalid in (
            "",
            valid + f"\n{required[0]}: test",
            valid.replace(f"{required[0]}: test", f"{required[0]}: benchmark"),
            valid.replace(required[0], run.PREFIX + "unexpected"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                run.check_listing(invalid, required)

    def test_exact_success_rejects_skips_zero_wrong_and_unexpected_exit(self):
        name = run.ORDINARY[0]
        output = successful_test(name)
        run.check_exact_test(outcome(output), name)
        for invalid in (
            outcome(output.replace("... ok", "... ignored")),
            outcome(output.replace("1 passed", "0 passed")),
            outcome(successful_test(run.ORDINARY[1])),
            outcome(output, code=1),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                run.check_exact_test(invalid, name)

    def test_cargo_selector_checks_unique_test_binary_inside_private_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            binary = target / "candidate"
            binary.touch(mode=0o700)
            outside = target.parent / "outside"
            outside.touch(mode=0o700)
            link = target / "symlink"
            link.symlink_to(outside)
            event = {
                "reason": "compiler-artifact", "target": {"name": "exacopy_platform", "kind": ["lib"]},
                "profile": {"test": True}, "executable": str(binary),
            }
            valid = json.dumps(event)
            self.assertEqual(run.executable_from_cargo(valid, target), binary)
            for invalid in (
                valid + "\n" + valid,
                json.dumps({**event, "executable": str(outside)}),
                json.dumps({**event, "executable": str(link)}),
                json.dumps({**event, "profile": {"test": False}}),
            ):
                with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                    run.executable_from_cargo(invalid, target)

    def test_unshare_blocked_does_not_count_fixture_success(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(run.shutil, "which", return_value="/synthetic-command"),
            patch.object(run.os, "readlink", return_value="mnt:[synthetic-parent]"),
            patch.object(
                run, "collect",
                return_value=outcome(stderr="unshare: unshare failed: Operation not permitted", code=1),
            ),
        ):
            root = Path(directory)
            with self.assertRaises(run.Blocked):
                run.run_mount(root, root, root / "test-binary")
            self.assertEqual((root / "mount.exit").read_text(), "1\n")

    def test_mount_success_requires_post_unmount_proof(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(run.shutil, "which", return_value="/synthetic-command"),
            patch.object(run.os, "readlink", return_value="mnt:[synthetic-parent]"),
            patch.object(run, "collect", return_value=outcome(successful_test(run.MOUNT_TEST))),
        ):
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "cleanup evidence is missing"):
                run.run_mount(root, root, root / "test-binary")

    def test_private_work_is_removed_even_after_failure(self):
        report = {}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                with run.private_work(directory, report) as work:
                    (work / "fixture").write_bytes(b"test")
                    raise RuntimeError("synthetic failure")
            self.assertFalse(work.exists())
        self.assertEqual(report, {"cleanup": "verified_absent"})

    def test_timeout_is_a_failure_and_retains_output(self):
        result = run.collect(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
            timeout=0.5,
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("started", result.stdout)
        self.assertIn("timed out", result.stderr)

    def test_failed_removal_does_not_report_an_uncreated_fixture(self):
        report = {}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(run.shutil, "rmtree", side_effect=OSError("removal refused")):
                with self.assertRaisesRegex(OSError, "removal refused"):
                    with run.private_work(directory, report) as work:
                        self.assertEqual(report["cleanup"], "pending")
                        (work / "fixture").write_bytes(b"test")
            self.assertTrue(work.exists())
            self.assertEqual(report["cleanup"], "failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Portable negative controls for the closed hosted component fixture."""

import json
import os
from pathlib import Path
import tempfile
import unittest

import run


class WitnessedComponents(unittest.TestCase):
    def test_manifest_refuses_selector_scope_and_binding_drift(self):
        fixture = run.HERE / "fixture.toml"
        run.binding(fixture)
        exact = fixture.read_text()
        for before, after in (
            (run.CASES[1], run.CASES[0]),
            ("ignored = true", "ignored = false"),
            (run.PROFILE, "some-other-profile"),
        ):
            with self.subTest(changed=before), tempfile.TemporaryDirectory() as directory:
                altered = Path(directory) / "fixture.toml"
                altered.write_text(exact.replace(before, after, 1))
                with self.assertRaisesRegex(ValueError, "manifest drift"):
                    run.binding(altered)

    def test_one_exact_test_requires_libtest_summary(self):
        case = run.CASES[0]
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s"
        output = f"running 1 test\ntest {case} ... ok\n{summary}\n"
        run.check_test(output, case)
        for altered in (
            output.replace(case, run.CASES[1]), output.replace("... ok", "... ignored"),
            output.replace("1 passed", "0 passed"), output + summary, output.replace(summary, ""),
        ):
            with self.subTest(output=altered), self.assertRaisesRegex(ValueError, "exactly one"):
                run.check_test(altered, case)
        run.check_listing(f"{case}: test\n", case)
        with self.assertRaisesRegex(ValueError, "listing mismatch"):
            run.check_listing(f"{case}: test\n{run.CASES[1]}: test\n", case)

    def test_cargo_executable_is_bound_to_package_and_private_target(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            target = work / "target"
            target.mkdir()
            binary = target / "test"
            binary.touch()
            event = {
                "reason": "compiler-artifact", "features": [],
                "target": {"name": "exacopy_platform", "kind": ["lib"],
                           "src_path": str(run.PACKAGE / "src/lib.rs")},
                "manifest_path": str(run.PACKAGE / "Cargo.toml"), "profile": {"test": True},
                "executable": str(binary),
            }
            self.assertEqual(run.artifact(json.dumps(event), target), binary)
            for key, value in (
                ("manifest_path", "/other/Cargo.toml"), ("features", ["experiment"]),
                ("profile", {"test": False}), ("executable", str(work / "other")),
            ):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    run.artifact(json.dumps({**event, key: value}), target)
            with self.assertRaisesRegex(ValueError, "expected one"):
                run.artifact("\n".join([json.dumps(event)] * 2), target)
            binary.unlink()
            other = work / "other"
            other.touch()
            binary.symlink_to(other)
            with self.assertRaisesRegex(ValueError, "escaped"):
                run.artifact(json.dumps(event), target)

    def test_cleanup_requires_empty_original_fixture_and_terminal_drain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            work, evidence = root / "work", root / "evidence"
            fixture = work / "fixture"
            fixture.mkdir(parents=True)
            evidence.mkdir()
            marker = evidence / "test.drain"
            marker.write_text("unconfirmed\n")
            work_id = run.ext4.inode(work)
            fd = os.open(fixture, run.ext4.DIR_FLAGS)
            try:
                with self.assertRaisesRegex(ValueError, "drain unconfirmed"):
                    run.cleanup(evidence, work, work_id, fixture, fd)
                marker.write_text("verified_absent\n")
                incumbent = fixture / "occupied"
                incumbent.touch()
                with self.assertRaisesRegex(ValueError, "fixture cleanup unconfirmed"):
                    run.cleanup(evidence, work, work_id, fixture, fd)
                self.assertTrue(incumbent.is_file())
                incumbent.unlink()
                fixture.rename(work / "old")
                fixture.mkdir()
                with self.assertRaisesRegex(ValueError, "fixture cleanup unconfirmed"):
                    run.cleanup(evidence, work, work_id, fixture, fd)
                fixture.rmdir()
                (work / "old").rename(fixture)
                run.cleanup(evidence, work, work_id, fixture, fd)
                self.assertFalse(work.exists())
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()

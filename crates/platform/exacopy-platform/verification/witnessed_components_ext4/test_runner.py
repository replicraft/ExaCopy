"""Portable negative controls for the closed hosted component fixture."""

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import run
from run import coverage_profile


class WitnessedComponents(unittest.TestCase):
    def test_checkpoint_helper_and_owned_vectors_are_bound_in_both_campaigns(self):
        import ordinary_coverage_cohorts as cohorts

        expected = (
            "src/linux/recovery/writer/witness_reservation/continuation/checkpoints/tests.rs",
            "src/linux/recovery/writer/witness_reservation/continuation/checkpoints/model_tests.rs",
            "src/linux/recovery/writer/witness_reservation/continuation/witness/component_tests.rs",
            "verification/witnessed_components_ext4/fixtures/checkpoint-journal.hex",
            "verification/witnessed_components_ext4/fixtures/checkpoint-successor.hex",
            "verification/witnessed_components_ext4/fixtures/README.md",
        )
        qualification = run.inputs()
        for relative in expected:
            source = run.PACKAGE / relative
            key = str(source.relative_to(run.ROOT))
            with self.subTest(source=relative):
                self.assertEqual(qualification[key], hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertIn(key, cohorts.SOURCE_INPUTS)

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


    def test_coverage_sinks_are_distinct_and_only_measured_profiles_are_retained(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            work = Path(directory).resolve()
            evidence = work / "evidence"
            evidence.mkdir()
            receipt = {}
            profiles = coverage_profile.Profiles(run.ext4, stack, work, evidence, receipt)
            profiles.prepare()
            base = {"TMPDIR": str(work / "fixture")}
            seen = set()
            for index, selector in enumerate(run.CASES, 1):
                for ending in ("listed", "ignored", "run"):
                    label = f"case-{index}-{ending}"
                    env = profiles.allocate(label, base)
                    path = Path(env["LLVM_PROFILE_FILE"])
                    self.assertEqual(env["TMPDIR"], base["TMPDIR"])
                    self.assertNotIn("LLVM_PROFILE_FILE", base)
                    self.assertEqual(path.parent.parent, work / "profiles")
                    self.assertNotIn(path, seen)
                    self.assertFalse(path.exists())
                    seen.add(path)
                    path.write_bytes(b"bounded custody control; LLVM validates raw framing")
                    profiles.collect(label, selector, "a" * 64)
            self.assertEqual(len(seen), 21)
            self.assertEqual(len(receipt["discarded_listing_profiles"]), 14)
            self.assertEqual([row["selector"] for row in receipt["admitted_profiles"]], list(run.CASES))
            self.assertEqual(len(list(evidence.glob("*.profraw"))), 7)
            profiles.check_cleanup()
            with self.assertRaisesRegex(ValueError, "repeated coverage sink"):
                profiles.allocate("case-1-run", base)

    def test_coverage_profile_refuses_missing_linked_empty_or_ambiguous_output(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            work = Path(directory).resolve()
            profiles = coverage_profile.Profiles(run.ext4, stack, work, work, {})
            profiles.prepare()
            label = "case-1-run"
            output = Path(profiles.allocate(label, {})["LLVM_PROFILE_FILE"])

            def collect():
                profiles.collect(label, run.CASES[0], "a" * 64)

            with self.assertRaisesRegex(ValueError, "exactly one"):
                collect()
            output.touch()
            with self.assertRaisesRegex(ValueError, "private regular file"):
                collect()
            output.write_bytes(b"bounded")
            alias = work / "alias"
            os.link(output, alias)
            with self.assertRaisesRegex(ValueError, "private regular file"):
                collect()
            alias.unlink()
            (output.parent / "other.profraw").touch()
            with self.assertRaisesRegex(ValueError, "exactly one"):
                collect()


    def test_instrumented_artifact_accepts_both_exact_pinned_cargo_layouts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            debug = root / run.TARGET / "debug"
            suffix = "41bef07687c54c85"
            name = f"exacopy_platform-{suffix}"
            version = tomllib.loads((run.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
            event = {
                "reason": "compiler-artifact", "fresh": False, "features": [],
                "package_id": f"path+{run.PACKAGE.as_uri()}#{version}",
                "manifest_path": str(run.PACKAGE / "Cargo.toml"), "profile": {"test": True},
                "target": {"name": "exacopy_platform", "kind": ["lib"], "crate_types": ["lib"],
                           "src_path": str(run.PACKAGE / "src/lib.rs"), "edition": "2024"},
            }

            def artifact(binary, **overrides):
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.touch()
                return {**event, "executable": str(binary), "filenames": [str(binary)], **overrides}

            build = debug / "build" / "exacopy-platform" / suffix / "out" / name
            for binary in (build, debug / "deps" / name):
                exact = artifact(binary)
                receipt = {}
                self.assertEqual(run.artifact(json.dumps(exact), root, coverage=receipt), binary)
                self.assertEqual(receipt["cargo_artifact"], exact)
            for invalid in (
                artifact(build.with_name("exacopy_platform-0123456789abcdef")),
                artifact(debug / "other" / name),
                artifact(debug / "deps" / "exacopy_platform-candidate"),
                artifact(build, filenames=[]),
                artifact(build, fresh=True),
                artifact(build, features=["other"]),
            ):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    run.artifact(json.dumps(invalid), root, coverage={})
            first = json.dumps(artifact(build))
            extra = json.dumps(artifact(debug / "deps" / name, features=["other"]))
            with self.assertRaisesRegex(ValueError, "expected one"):
                run.artifact(f"{first}\n{extra}", root, coverage={})

    def test_cleanup_rechecks_discarded_listing_inode(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            temp = Path(directory).resolve()
            work, evidence = temp / "work", temp / "evidence"
            work.mkdir()
            evidence.mkdir()
            work_id = run.ext4.inode(work)
            profiles = coverage_profile.Profiles(run.ext4, stack, work, evidence, {})
            profiles.prepare()
            label = "case-1-listed"
            output = Path(profiles.allocate(label, {})["LLVM_PROFILE_FILE"])
            output.write_bytes(b"discarded")
            profiles.collect(label, run.CASES[0], "a" * 64)
            output.rename(work / "original")
            output.write_bytes(b"discarded")
            with self.assertRaisesRegex(ValueError, "held private regular file"):
                run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
            self.assertEqual(output.read_bytes(), b"discarded")
            self.assertEqual((work / "original").read_bytes(), b"discarded")

    def test_cleanup_preserves_uncollected_outputs_and_partial_profile_root(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            temp = Path(directory).resolve()
            evidence = temp / "evidence"
            evidence.mkdir()
            for index, kind in enumerate(("symlink", "hardlink", "directory", "file", "partial-root")):
                work = temp / f"work-{index}"
                work.mkdir()
                work_id = run.ext4.inode(work)
                profiles = coverage_profile.Profiles(run.ext4, stack, work, evidence, {})
                if kind == "partial-root":
                    with patch.object(profiles, "open_directory", side_effect=OSError("cannot hold root")):
                        with self.assertRaisesRegex(OSError, "cannot hold root"):
                            profiles.prepare()
                    with self.assertRaisesRegex(ValueError, "root custody unconfirmed"):
                        run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
                    self.assertTrue(profiles.root_path.is_dir())
                    continue
                profiles.prepare()
                output = Path(profiles.allocate("case-1-run", {})["LLVM_PROFILE_FILE"])
                original = work / "original"
                original.write_bytes(b"uncollected")
                if kind == "symlink":
                    output.symlink_to(original)
                if kind == "hardlink":
                    os.link(original, output)
                if kind == "directory":
                    output.mkdir()
                if kind == "file":
                    output.write_bytes(b"uncollected")
                with self.assertRaisesRegex(ValueError, "uncollected coverage output"):
                    run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
                self.assertTrue(os.path.lexists(output))
                self.assertEqual(original.read_bytes(), b"uncollected")

    def test_cleanup_preserves_unadmitted_merge_output(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            temp = Path(directory).resolve()
            work, evidence = temp / "work", temp / "evidence"
            work.mkdir()
            evidence.mkdir()
            work_id = run.ext4.inode(work)
            profiles = coverage_profile.Profiles(run.ext4, stack, work, evidence, {})
            profiles.prepare()
            index = profiles.begin_merge()
            self.assertEqual(index.parent.parent, work / "profiles")
            self.assertFalse(os.path.lexists(index))
            profiles.check_cleanup()

            index.touch()
            with self.assertRaisesRegex(ValueError, "held private regular file"):
                profiles.collect_index()
            with self.assertRaisesRegex(ValueError, "uncollected coverage output"):
                run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
            self.assertTrue(index.is_file())

            index.unlink()
            original = work / "incumbent"
            original.write_bytes(b"unadmitted index")
            index.symlink_to(original)
            with self.assertRaises(OSError):
                profiles.collect_index()
            with self.assertRaisesRegex(ValueError, "uncollected coverage output"):
                run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
            self.assertEqual(index.readlink(), original)
            self.assertEqual(original.read_bytes(), b"unadmitted index")

    def test_cleanup_rechecks_owned_merged_index_until_removal(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            temp = Path(directory).resolve()
            work, evidence = temp / "work", temp / "evidence"
            work.mkdir()
            evidence.mkdir()
            work_id = run.ext4.inode(work)
            report = {}
            profiles = coverage_profile.Profiles(run.ext4, stack, work, evidence, report)
            profiles.prepare()
            index = profiles.begin_merge()
            data = b"owned merged profile custody control"
            index.write_bytes(data)
            fd = profiles.collect_index()
            self.assertEqual(os.pread(fd, len(data), 0), data)
            self.assertEqual(report["merged_profile"]["retained"], index.name)
            self.assertEqual((evidence / index.name).read_bytes(), data)
            profiles.check_cleanup()

            original = work / "original-index"
            index.rename(original)
            index.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "held private regular file"):
                run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
            self.assertEqual(original.read_bytes(), data)
            self.assertEqual(index.read_bytes(), data)
            index.unlink()
            original.rename(index)
            run.cleanup(evidence, work, work_id, work / "fixture", None, profiles=profiles)
            self.assertFalse(work.exists())
            self.assertEqual((evidence / index.name).read_bytes(), data)

    def test_llvm_export_requires_typed_versioned_finite_unique_data(self):
        name = f"{coverage_profile.SOURCE_PREFIX}linux.rs"
        summary = {"count": 2, "covered": 1, "notcovered": 1, "percent": 50}
        row = {"filename": name, "summary": {"lines": summary, "regions": summary}}
        report = {"type": coverage_profile.EXPORT_TYPE, "version": coverage_profile.EXPORT_VERSION,
                  "data": [{"files": [row, {"filename": "other/crate.rs"}]}]}
        coverage_profile.summarize(coverage_profile.parse_export(json.dumps(report)), run.ROOT, [name], [])
        for invalid in (
            None,
            report | {"version": "0.0.0"},
            report | {"data": [None]},
            report | {"data": [{"files": [row | {"summary": None}]}]},
            report | {"data": [{"files": [row | {"filename": False}]}]},
            report | {"data": [{"files": [row, row]}]},
            report | {"data": [{"files": [row | {"summary": {
                "lines": summary | {"covered": True}, "regions": summary,
            }}]}]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                coverage_profile.summarize(invalid, run.ROOT, [name], [])
        for invalid in ('{"field":0,"field":1}', '{"metric":NaN}', '{"metric":1e999}'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                coverage_profile.parse_export(invalid)


    def test_llvm_export_excludes_only_linked_tracked_platform_test_sources(self):
        root = Path("/checked/repository")
        source_prefix = coverage_profile.SOURCE_PREFIX
        test_prefix = coverage_profile.TEST_PREFIX
        crate_prefix = coverage_profile.CRATE_PREFIX
        name = f"{source_prefix}linux.rs"
        scratch = f"{test_prefix}common/scratch.rs"
        journal = f"{test_prefix}unit/journal_segment.rs"
        scratch_alias = f"{source_prefix}../tests/common/scratch.rs"
        journal_alias = f"{source_prefix}linux/../../tests/unit/journal_segment.rs"
        summary = {"count": 2, "covered": 1, "notcovered": 1, "percent": 50}
        fixture_counts = {"count": 100, "covered": 100, "notcovered": 0, "percent": 100}
        row = {"filename": name, "summary": {"lines": summary, "regions": summary}}

        def mapping(*aliases, tracked_tests=(scratch, journal)):
            test_rows = [{"filename": str(path),
                          "summary": {"lines": fixture_counts, "regions": fixture_counts}}
                         for path in aliases]
            export = {"type": coverage_profile.EXPORT_TYPE, "version": coverage_profile.EXPORT_VERSION,
                      "data": [{"files": [row, *test_rows]}]}
            return coverage_profile.summarize(export, root, [name], tracked_tests)

        result = mapping(root / scratch_alias, journal_alias)
        self.assertEqual(result["tracked_test_source_inventory"], (scratch, journal))
        self.assertEqual(result["excluded_linked_test_mappings"],
                         {scratch_alias: scratch, journal_alias: journal})
        self.assertEqual(list(result["files"]), [name])
        self.assertEqual(result["totals_for_mapped_sources"]["lines"],
                         {"total": 2, "covered": 1, "uncovered": 1})

        for invalid in (
            f"{source_prefix}../tests/untracked.rs",
            f"{source_prefix}linux/../linux.rs",
            f"{source_prefix}./linux.rs",
            f"{source_prefix}/linux.rs",
            f"{source_prefix}../tests/./common/scratch.rs",
            f"{source_prefix}../../exacopy-platform/tests/common/scratch.rs",
            f"{source_prefix}../../other/tests/common/scratch.rs",
            f"{crate_prefix}tests/../src/linux.rs",
            f"unrelated/../{name}",
            f"../repository/{name}",
            f"/checked/other/../repository/{name}",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                mapping(invalid)
        with self.assertRaisesRegex(ValueError, "tracked owning-crate test source"):
            mapping(scratch_alias, tracked_tests=())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mapping(scratch_alias, root / scratch_alias)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            mapping(root / name)


if __name__ == "__main__":
    unittest.main()

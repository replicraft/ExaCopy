"""Portable controls for exact genesis runner admission and evidence projection."""

import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "crates/platform/exacopy-platform/verification/sync_history_ext4"))
import genesis_format_controls as codec
import run


class OracleCleanupUnconfirmed(RuntimeError):
    pass


class Controls(unittest.TestCase):
    parent = Path("/private/fixture")
    pid = 194
    facts = {
        "boot": "00000000-0000-0000-0000-000000000001",
        "mount_namespace": "4:10", "user_namespace": "4:11", "parent": "2049:5",
        "mount": 25, "unique_mount": 5021, "effective_uid": 1000, "effective_gid": 1001,
    }
    anchors = {"left": "2049:6", "right": "2049:7"}
    receipt = {
        "schema_version": 1, "outcome": "pass", "member_count": 4,
        "root_sha256": "a" * 64, "root_digest": "b" * 64, "intent_sha256": "c" * 64,
    }

    def transcript(self, marker="passed controls=8 cleanup=verified", frame="{}", *, blocked=False):
        evidence = f"{run.GENESIS_FRAME}{frame}\n" if frame is not None else ""
        completed = ("FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;" if blocked
                     else "ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;")
        return (f"\nrunning 1 test\ntest {run.GENESIS.case} ... \n{evidence}"
                f"{run.GENESIS_MARKER}{marker}\n{completed} 0 measured; 0 filtered out; finished in 0.31s\n")

    def check(self, output, code=0, *, pid=None, oracle=None, parser=None, report=None):
        if pid is None:
            pid = self.pid
        if oracle is None:
            oracle = Mock()
            oracle.verify_frame.return_value = self.receipt
        return run.checked_genesis_result(
            output, code, self.facts, self.anchors, self.parent, pid, oracle, parser or json.loads, report=report,
        )

    def test_genesis_fixture_and_profile_are_separate(self):
        self.assertRegex(run.manifest_digest(run.GENESIS), r"^[0-9a-f]{64}$")
        self.assertTrue(run.has_managed_substrate(run.GENESIS))
        self.assertTrue(run.has_managed_substrate(run.MANAGED))
        self.assertFalse(run.has_managed_substrate(run.HISTORY))
        self.assertFalse(run.has_managed_substrate(run.STATMOUNT))
        self.assertNotEqual(run.GENESIS.definition, run.MANAGED.definition)
        self.assertNotEqual(run.GENESIS.parent_variable, run.MANAGED.parent_variable)
        with patch.object(Path, "read_bytes", return_value=run.MANAGED.definition.read_bytes()):
            with self.assertRaisesRegex(ValueError, "manifest drift"):
                run.manifest_digest(run.GENESIS)

    def test_only_exact_genesis_cargo_artifact_admits(self):
        profile = run.GENESIS
        root = Path("/private/target")
        path = root / run.TARGET / "debug/deps" / (profile.test + "-a0123456789bcdef")
        event = {
            "reason": "compiler-artifact", "executable": str(path), "fresh": False,
            "package_id": f"path+{profile.package_root.as_uri()}#0.1.0",
            "manifest_path": str(profile.package_root / "Cargo.toml"), "profile": {"test": True},
            "features": [profile.required_feature],
            "target": {"name": profile.test, "kind": ["test"], "edition": "2024", "crate_types": ["bin"],
                       "src_path": str(profile.package_root / "tests" / f"{profile.test}.rs")},
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(run.artifact(json.dumps(event), root, profile), path)
            build_path = path.parent.parent / "build/exacopy-cli/0123456789abcdef/out" / path.name
            self.assertEqual(run.artifact(json.dumps(event | {"executable": str(build_path)}), root, profile),
                             build_path)
            for change in (
                {"features": []}, {"features": [profile.required_feature, "extra"]},
                {"fresh": True}, {"package_id": event["package_id"] + "-other"},
                {"profile": {"test": False}}, {"executable": str(root / path.name)},
                {"target": event["target"] | {"name": run.MANAGED.test}},
            ):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    run.artifact(json.dumps(event | change), root, profile)
            for extra in (event, event | {"features": []}):
                with self.assertRaises(ValueError):
                    run.artifact("\n".join((json.dumps(event), json.dumps(extra))), root, profile)
        with patch.object(Path, "resolve", return_value=path.with_name("rebound")), self.assertRaises(ValueError):
            run.artifact(json.dumps(event), root, profile)

    def test_exact_frame_binds_held_launch_pid_mount_actor_and_anchors(self):
        oracle = Mock()
        oracle.verify_frame.return_value = self.receipt
        frame = '{"synthetic":true}'
        result = self.check(self.transcript(frame=frame), oracle=oracle)
        oracle.verify_frame.assert_called_once_with(
            {"synthetic": True},
            {"fixture_parent": self.parent, "pid": self.pid, "boot": self.facts["boot"],
             "mount_namespace": "4:10", "user_namespace": "4:11", "parent": "2049:5",
             "mount": 25, "unique_mount": 5021, "actor": (1000, 1001), "anchors": ("2049:6", "2049:7")},
        )
        self.assertEqual(result["frame_sha256"], hashlib.sha256(frame.encode()).hexdigest())
        self.assertEqual(result["oracle"], self.receipt)
        self.assertEqual(result["outcome"], "passed")

    def test_missing_duplicate_oversized_or_denied_frame_cannot_pass(self):
        valid = self.transcript()
        parser = Mock(side_effect=ValueError("strict parser refused duplicate key"))
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            self.check(self.transcript(frame='{"x":1,"x":2}'), parser=parser)
        for output in (
            self.transcript(frame=None), self.transcript(frame="é" * (1 + run.GENESIS_FRAME_LIMIT // 2)),
            valid + f"{run.GENESIS_FRAME}{{}}\n", valid + f"{run.GENESIS_MARKER}passed\n",
            self.transcript(marker="passed controls=7 cleanup=verified"),
            valid.replace(f"{run.GENESIS_FRAME}{{}}\n", "") + f"{run.GENESIS_FRAME}{{}}\n",
            valid.replace(run.GENESIS.case, run.MANAGED.case),
        ):
            with self.subTest(length=len(output)), self.assertRaises(ValueError):
                self.check(output)
        oracle = Mock()
        oracle.verify_frame.side_effect = ValueError("independent observed mount differs")
        evidence = {}
        with self.assertRaisesRegex(ValueError, "observed mount differs"):
            self.check(valid, oracle=oracle, report=evidence)
        self.assertEqual(evidence["frame_sha256"], hashlib.sha256(b"{}").hexdigest())
        oracle.verify_frame.side_effect = None
        oracle.verify_frame.return_value = self.receipt | {"member_count": 3}
        with self.assertRaisesRegex(ValueError, "independent genesis oracle receipt"):
            self.check(valid, oracle=oracle)
        with self.assertRaisesRegex(ValueError, "process identity"):
            self.check(valid, pid=True)

    def test_only_exact_typed_mount_refusal_is_blocked(self):
        for reason in ("statmount-attributes-unavailable", "idmapped-history-mount"):
            blocked = self.transcript(f"blocked reason={reason}", frame=None, blocked=True)
            oracle = Mock()
            self.assertEqual(self.check(blocked, 101, oracle=oracle)["outcome"], "blocked")
            oracle.verify_frame.assert_not_called()
            for output, code in (
                (blocked, 0), (blocked, 77), (blocked.replace(reason, "other"), 101),
                (blocked + f"{run.GENESIS_FRAME}{{}}\n", 101),
            ):
                with self.subTest(code=code), self.assertRaises(ValueError):
                    self.check(output, code, oracle=oracle)

    def test_refuses_extra_or_inexact_libtest_summaries(self):
        passed = self.transcript()
        blocked = self.transcript("blocked reason=idmapped-history-mount", frame=None, blocked=True)
        for output, code in (
            (passed, 0), (blocked, 101),
        ):
            summary = next(line for line in output.splitlines() if line.startswith("test result: "))
            self.assertEqual(self.check(output, code)["outcome"], "passed" if code == 0 else "blocked")
            for wrong in (
                output + summary + "\n",
                output.replace(summary, "test result: FAILED. bogus\n" + summary),
                output.replace("0 filtered out", "1 filtered out"),
                output.replace("0 measured", "1 measured"),
            ):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    self.check(wrong, code)

    def test_oracle_preflight_follows_proc_admission_and_precedes_allocation(self):
        class Unavailable(RuntimeError):
            pass

        ready = Mock(prerequisites={"openssl_sha256": "7" * 64})
        module = SimpleNamespace(preflight=Mock(), OracleUnavailable=Unavailable, parse_frame=Mock(),
                                 OracleCleanupUnconfirmed=OracleCleanupUnconfirmed)
        order = Mock()
        order.attach_mock(module.preflight, "preflight")
        args = ("a" * 40, self.parent, Path("/evidence"), {}, run.GENESIS)
        with (patch.object(run, "check_revision"),
              patch.object(run, "manifest_digest", return_value="1" * 64),
              patch.object(run.os, "open", return_value=7),
              patch.object(run.os, "close"),
              patch.object(run.os, "fstat", return_value=SimpleNamespace(st_uid=1000, st_mode=0o700)),
              patch.object(run.os, "geteuid", return_value=1000),
              patch.object(run, "observe", return_value=self.facts) as observe,
              patch.object(run, "qualify_admitted", side_effect=ValueError("after preflight")) as admitted):
            order.attach_mock(observe, "observe")
            observe.side_effect = run.Blocked("unverified proc custody")
            with self.assertRaisesRegex(run.Blocked, "unverified proc custody"):
                run.qualify(*args, genesis_oracle=module)
            module.preflight.assert_not_called()
            admitted.assert_not_called()
            observe.side_effect = None
            order.reset_mock()
            module.preflight.side_effect = Unavailable()
            with self.assertRaisesRegex(run.Blocked, "oracle prerequisite unavailable"):
                run.qualify(*args, genesis_oracle=module)
            admitted.assert_not_called()
            self.assertEqual([call[0] for call in order.mock_calls], ["observe", "preflight"])
            module.preflight.side_effect = OracleCleanupUnconfirmed("tool cleanup")
            with self.assertRaisesRegex(OracleCleanupUnconfirmed, "tool cleanup"):
                run.qualify(*args, genesis_oracle=module)
            self.assertEqual(args[3]["oracle_cleanup"], "unconfirmed")
            admitted.assert_not_called()
            module.preflight.side_effect = None
            module.preflight.return_value = ready
            with self.assertRaisesRegex(ValueError, "after preflight"):
                run.qualify(*args, genesis_oracle=module)
            self.assertEqual(args[3]["oracle_prerequisites"], ready.prerequisites)
            ready.close.assert_called_once_with()

    def test_genesis_launch_has_no_companion_and_requires_stable_custody(self):
        binary = Path("/private/test-harness")
        elf = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00"
        image = SimpleNamespace(read=lambda _size: elf, fileno=lambda: 10)
        stat_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_size=20)
        held = ((8, 10), "a" * 64)

        def launch(_evidence, label, _args, **options):
            self.assertEqual(options["held"], (10,))
            self.assertEqual(options["executable"], "/proc/self/fd/10")
            if label != "run":
                return f"{run.GENESIS.case}: test"
            self.assertEqual(options["output_limit"], run.GENESIS_TRANSCRIPT_LIMIT)
            options["started"](self.pid)
            if scenario == "timeout":
                raise TimeoutError("run expired")
            self.assertEqual(_args[-1], run.GENESIS.case)
            return self.transcript(), 0

        for scenario in ("pass", "timeout", "stamp", "oracle_cleanup"):
            final = (held[0], "e" * 64) if scenario == "stamp" else held
            with (self.subTest(scenario=scenario),
                  patch.object(run.os, "open", return_value=10),
                  patch.object(run.os, "fdopen") as opened,
                  patch.object(run.os, "fstat", return_value=stat_info),
                  patch.object(run, "held_managed_image", side_effect=(held, held, final)),
                  patch.object(run, "command", side_effect=launch),
                  patch.object(run, "checked_genesis_result", return_value={"outcome": "passed"}) as result):
                opened.return_value.__enter__.return_value = image
                report = {}
                args = (Path("/evidence"), binary, {}, self.facts, report, run.GENESIS, self.anchors)
                genesis = (self.parent, Mock(), Mock(), OracleCleanupUnconfirmed)
                if scenario == "pass":
                    run.execute(*args, genesis=genesis)
                    self.assertEqual(result.call_args.args[5], self.pid)
                    self.assertEqual(report["case"], {"outcome": "passed"})
                    self.assertNotIn("cli_executable", report)
                elif scenario == "oracle_cleanup":
                    result.side_effect = OracleCleanupUnconfirmed("oracle child may still be running")
                    with self.assertRaisesRegex(OracleCleanupUnconfirmed, "child may still be running"):
                        run.execute(*args, genesis=genesis)
                    self.assertEqual(report["cleanup"], "cleanup_failed")
                    self.assertEqual(report["oracle_cleanup"], "unconfirmed")
                    with patch.object(run.shutil, "rmtree") as remove:
                        run.finish_owned_work(None, None, None, None, None, None, report)
                        remove.assert_not_called()
                elif scenario == "timeout":
                    with self.assertRaisesRegex(TimeoutError, "run expired"):
                        run.execute(*args, genesis=genesis)
                    result.assert_not_called()
                else:
                    with self.assertRaisesRegex(ValueError, "harness changed after execution"):
                        run.execute(*args, genesis=genesis)
                    result.assert_not_called()
                self.assertEqual(report["launch_pid"], self.pid)
                if scenario != "pass":
                    self.assertNotIn("case", report)


class FormatControlTests(unittest.TestCase):
    def test_requires_one_exact_native_platform_libtest_artifact(self):
        root = Path("/private/target")
        native = root / run.TARGET / "debug"
        suffix = "a0123456789bcdef"
        path = native / "build" / codec.PACKAGE_NAME / suffix / "out" / f"{codec.LIBRARY}-{suffix}"
        event = {
            "reason": "compiler-artifact", "executable": str(path), "filenames": [str(path)],
            "fresh": False, "package_id": f"path+{run.PACKAGE.as_uri()}#0.1.0",
            "manifest_path": str(run.PACKAGE / "Cargo.toml"), "profile": {"test": True},
            "features": [codec.FEATURE],
            "target": {"name": codec.LIBRARY, "kind": ["lib"], "crate_types": ["lib"],
                       "src_path": str(run.PACKAGE / "src/lib.rs"), "edition": "2024"},
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(codec.artifact(run, json.dumps(event), root), path)
            alternate = native / "deps" / path.name
            direct = event | {"executable": str(alternate), "filenames": [str(alternate)]}
            self.assertEqual(codec.artifact(run, json.dumps(direct), root), alternate)
            for change in (
                {"features": []}, {"features": [codec.FEATURE, "extra"]}, {"fresh": True},
                {"package_id": event["package_id"] + "-other"}, {"profile": {"test": False}},
                {"manifest_path": str(run.CLI_PACKAGE / "Cargo.toml")}, {"filenames": []},
                {"target": event["target"] | {"src_path": str(run.CLI_PACKAGE / "src/lib.rs")}},
                {"target": event["target"] | {"kind": ["test"]}},
            ):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    codec.artifact(run, json.dumps(event | change), root)
            escaped = path.with_name("exacopy_platform-0123456789abcdef")
            for candidate in (escaped, Path("/foreign") / path.name):
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    codec.artifact(run, json.dumps(event | {"executable": str(candidate),
                                                           "filenames": [str(candidate)]}), root)
            for extra in (event, event | {"features": []}):
                with self.assertRaises(ValueError):
                    codec.artifact(run, "\n".join(map(json.dumps, [event, extra])), root)
        with patch.object(Path, "resolve", return_value=path.with_name("rebound")), self.assertRaises(ValueError):
            codec.artifact(run, json.dumps(event), root)

    def test_requires_exact_nonignored_attendance_and_summary(self):
        case = codec.CASES[0]
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 166 filtered out; finished in 0.01s"
        stdout = f"\nrunning 1 test\ntest {case} ... ok\n\n{summary}\n"
        codec.check_test(run, stdout, case)
        for invalid in (
            stdout.replace("running 1 test", "running 0 tests"), stdout.replace(" ... ok", " ... ignored"),
            stdout.replace(case, codec.CASES[1]), stdout + summary,
            stdout.replace("0 ignored", "1 ignored"),
            f"running 1 test\n{summary}\ntest {case} ... ok\n",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                codec.check_test(run, invalid, case)

    def test_format_driver_stops_at_missing_control_and_records_four_only_on_success(self):
        work = Path("/private/work")
        binary = work / "target/test-image"
        report = {}
        missing_index = 3

        def command(_evidence, label, args, **kwargs):
            if label == "format-cargo":
                self.assertIn("--lib", args)
                self.assertIn("--offline", args)
                self.assertIn("--locked", args)
                self.assertIn("--no-default-features", args)
                self.assertEqual(args[args.index("--features") + 1], codec.FEATURE)
                self.assertEqual(kwargs["env"], {"selected-build-env": "true"})
                return ""
            self.assertEqual(kwargs["held"], (12,))
            self.assertEqual(kwargs["executable"], "/proc/self/fd/12")
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work)})
            _, _, ordinal, phase = label.split("-")
            case = codec.CASES[int(ordinal) - 1]
            self.assertEqual(args[-1], case)
            self.assertIn("--exact", args)
            if phase == "listed":
                return f"{case}: test\n"
            if phase == "ignored":
                return f"{case}: test\n" if int(ordinal) == missing_index else ""
            self.assertNotIn("--ignored", args)
            return (f"running 1 test\ntest {case} ... ok\n"
                    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 166 filtered out; finished in 0.01s")

        with (patch.object(codec, "artifact", return_value=binary),
              patch.object(codec, "inputs", return_value={"oracle": "b" * 64}),
              patch.object(codec.os, "open", return_value=12),
              patch.object(codec.os, "close") as close,
              patch.object(run, "held_managed_image", return_value=((), "a" * 64)),
              patch.object(run, "command", side_effect=command) as invoked):
            args = (run, work / "evidence", work / "target", {"selected-build-env": "true"}, work, report)
            with self.assertRaisesRegex(ValueError, "ignored inventory"):
                codec.run(*args)
            self.assertEqual(tuple(report["format_controls"]["cases"]), codec.CASES[:2])
            self.assertEqual(report["format_controls"]["outcome"], "failed")
            self.assertEqual(invoked.call_args.args[1], "format-case-3-ignored")
            missing_index = None
            codec.run(*args)
            self.assertEqual(invoked.call_args.args[1], "format-case-4-run")
            self.assertEqual(tuple(report["format_controls"]["cases"]), codec.CASES)
            self.assertEqual(report["format_controls"]["outcome"], "passed")
            self.assertEqual(close.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

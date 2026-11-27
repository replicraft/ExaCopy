"""Portable controls for the managed production qualification envelope."""

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "crates/platform/exacopy-platform/verification/sync_history_ext4"))
import run


def identity(major, minor, inode):
    return f"{os.makedev(major, minor)}:{inode}"


class Controls(unittest.TestCase):
    def test_exact_managed_app_artifact_is_isolated_from_platform_profiles(self):
        profile = run.MANAGED
        self.assertRegex(run.manifest_digest(profile), r"^[0-9a-f]{64}$")
        self.assertEqual(profile.package_root, ROOT / "apps/exacopy-cli")
        target = Path("/private/test-target")
        event = {
            "reason": "compiler-artifact", "executable": str(target / "program"),
            "manifest_path": str(profile.package_root / "Cargo.toml"), "profile": {"test": True},
            "target": {"name": profile.test, "kind": ["test"],
                       "src_path": str(profile.package_root / "tests" / f"{profile.test}.rs")},
            "features": [profile.required_feature],
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(run.artifact(json.dumps(event), target, profile), target / "program")
            for wrong in (
                {**event, "manifest_path": str(run.PACKAGE / "Cargo.toml")},
                {**event, "target": {**event["target"], "src_path": str(run.PACKAGE / "tests" / f"{profile.test}.rs")}},
                {**event, "features": []},
                {**event, "features": [profile.required_feature, "unrelated"]},
                {**event, "profile": {"test": False}},
                {**event, "executable": str(target.parent / "program")},
            ):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    run.artifact(json.dumps(wrong), target, profile)
            for old in (run.HISTORY, run.STATMOUNT):
                with self.subTest(old=old.id), self.assertRaises(ValueError):
                    run.artifact(json.dumps(event), target, old)
            with self.assertRaises(ValueError):
                run.artifact("\n".join((json.dumps(event), json.dumps(event))), target, profile)

    def test_success_binds_admission_facts_and_selected_control_inventory(self):
        facts, anchors = self.observations()
        success = self.output(
            "passed boot=00000000-0000-0000-0000-000000000001 mnt_ns=0:4:10 user_ns=0:4:11 "
            "mount=25 unique_mount=5021 anchor=8:1:5 anchor_left=8:1:6 anchor_right=8:1:7 "
            "live=8:1:8 live_left=8:1:9 live_right=8:1:10 controls=7 cleanup=verified",
        )
        result = run.checked_managed_result(success, 0, facts, anchors)
        self.assertEqual((result["outcome"], result["feature"], result["controls"]),
                         ("passed", run.MANAGED.required_feature, 7))
        for old, new in (
            ("000000000001", "000000000002"), ("mnt_ns=0:4:10", "mnt_ns=0:4:9"),
            ("user_ns=0:4:11", "user_ns=0:4:9"), ("mount=25", "mount=24"),
            ("unique_mount=5021", "unique_mount=5022"), ("anchor=8:1:5", "anchor=8:1:6"),
            ("anchor_left=8:1:6", "anchor_left=8:1:7"), ("anchor_right=8:1:7", "anchor_right=8:1:6"),
            ("live=8:1:8", "live=8:2:8"), ("live_left=8:1:9", "live_left=8:1:6"),
            ("live_right=8:1:10", "live_right=8:1:18446744073709551616"),
            ("controls=7", "controls=6"), (" controls=7", ""), (" live_left=8:1:9", ""),
            ("cleanup=verified", "cleanup=unconfirmed"),
            ("running 1 test", "running 0 tests"), (run.MANAGED.case, "unrelated_case"),
            ("0 ignored", "1 ignored"),
        ):
            with self.subTest(old=old), self.assertRaises(ValueError):
                run.checked_managed_result(success.replace(old, new), 0, facts, anchors)
        for output, code in ((success, 101), (success + success, 0)):
            with self.assertRaises(ValueError):
                run.checked_managed_result(output, code, facts, anchors)

    def test_unsupported_fixture_is_typed_nonpassing(self):
        facts, anchors = self.observations()
        for reason in ("statmount-attributes-unavailable", "idmapped-history-mount"):
            blocked = self.output(f"blocked reason={reason}", blocked=True)
            result = run.checked_managed_result(blocked, 101, facts, anchors)
            self.assertEqual((result["outcome"], result["reason"]), ("blocked", reason))
            for output, code in ((blocked, 0), (blocked, 77),
                                 (blocked.replace(reason, "other"), 101),
                                 (blocked.replace("1 failed", "0 failed"), 101)):
                with self.assertRaises(ValueError):
                    run.checked_managed_result(output, code, facts, anchors)

    def test_actor_requires_exact_named_proc_fields_full_maps_and_unambiguous_ids(self):
        state = b"Uid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n"
        proc = {"uid_map": b"         0          0 4294967295\n",
                "gid_map": b"         0          0 4294967295\n",
                "sys/kernel/overflowuid": b"65534\n", "sys/kernel/overflowgid": b"65534\n"}

        def observe(status, values):
            read = lambda scope, path, bound: values[path]
            return run.managed_actor(status, read, 1, 2, Path("/evidence"), "mock")

        with (patch.object(run.os, "getuid", return_value=1000), patch.object(run.os, "geteuid", return_value=1000),
              patch.object(run.os, "getgid", return_value=1001), patch.object(run.os, "getegid", return_value=1001),
              patch.object(Path, "write_bytes")):
            got = observe(state, proc)
            self.assertEqual(got, {"real_gid": 1001, "effective_gid": 1001, "identity_maps": "full"})
            for status, values in ((state + state, proc), (state.replace(b"1000", b"1002", 1), proc),
                                   (state, {**proc, "gid_map": b"0 1000 1\n"}),
                                   (state, {**proc, "uid_map": b"0 0 4294967295\n\n"}),
                                   (state, {**proc, "sys/kernel/overflowgid": b"1001\n"})):
                with self.assertRaises(run.Blocked):
                    observe(status, values)

    @staticmethod
    def observations():
        return ({
            "boot": "00000000-0000-0000-0000-000000000001", "mount": 25, "unique_mount": 5021,
            "mount_namespace": identity(0, 4, 10), "user_namespace": identity(0, 4, 11),
            "parent": identity(8, 1, 5),
        }, {"left": identity(8, 1, 6), "right": identity(8, 1, 7)})

    @staticmethod
    def output(marker, blocked=False):
        body = ("FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;" if blocked
                else "ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;")
        return (f"\nrunning 1 test\ntest {run.MANAGED.case} ... \n{run.MANAGED_MARKER}{marker}\n"
                f"{body} 0 measured; 0 filtered out\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)

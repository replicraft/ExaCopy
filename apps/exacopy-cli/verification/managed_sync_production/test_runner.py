"""Portable controls for the managed production qualification envelope."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "crates/platform/exacopy-platform/verification/sync_history_ext4"))
import run


def identity(major, minor, inode):
    return f"{os.makedev(major, minor)}:{inode}"


class Controls(unittest.TestCase):
    cli_sha256 = "a5" * 32

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

    def test_exact_cargo_cli_artifact_rejects_wrong_provenance_and_extra_candidates(self):
        target = Path("/private/target")
        path = target / run.TARGET / "debug/exacopy"
        event = {
            "reason": "compiler-artifact", "executable": str(path),
            "package_id": f"path+{run.CLI_PACKAGE.as_uri()}#0.1.0",
            "manifest_path": str(run.CLI_PACKAGE / "Cargo.toml"),
            "profile": {"test": False}, "features": [run.MANAGED.required_feature], "fresh": False,
            "target": {"name": "exacopy", "kind": ["bin"], "crate_types": ["bin"], "edition": "2024",
                       "src_path": str(run.CLI_PACKAGE / "src/main.rs")},
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(run.managed_cli_artifact(json.dumps(event), target), path)
            for change in (
                {"package_id": event["package_id"] + "-other"},
                {"manifest_path": str(run.PACKAGE / "Cargo.toml")},
                {"target": event["target"] | {"src_path": str(run.CLI_PACKAGE / "src/lib.rs")}},
                {"profile": {"test": True}},
                {"features": []},
                {"features": [run.MANAGED.required_feature, "extra"]},
                {"fresh": True},
                {"executable": str(path.with_name("alias"))},
            ):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    run.managed_cli_artifact(json.dumps(event | change), target)
            with self.assertRaises(ValueError):
                run.managed_cli_artifact(f"{json.dumps(event)}\n{json.dumps(event)}", target)
        with patch.object(Path, "resolve", return_value=path.with_name("alias")):
            with self.assertRaises(ValueError):
                run.managed_cli_artifact(json.dumps(event), target)

    def test_held_cli_checks_exact_name_elf_hash_and_read_bound(self):
        fd = 11
        path = Path("/private/target/exacopy")
        elf = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + b"body"
        metadata = dict(
            st_dev=8, st_ino=9, st_uid=1000, st_gid=1000, st_nlink=1,
            st_mode=stat.S_IFREG | 0o755, st_size=len(elf), st_mtime_ns=1, st_ctime_ns=2,
        )
        node = SimpleNamespace(**metadata)
        with (patch.object(run.os, "geteuid", return_value=1000),
              patch.object(run.os, "fstat", return_value=node) as held,
              patch.object(Path, "stat", return_value=node) as named,
              patch.object(run.os, "pread", side_effect=lambda _fd, size, offset: elf[offset:offset + size]) as read):
            observed = run.held_managed_image(path, fd, run.MANAGED_CLI_LIMIT)
            digest = hashlib.sha256(elf).hexdigest()
            self.assertEqual(observed[1], digest)
            env, facts = run.managed_cli_environment(fd, observed)
            self.assertEqual(env["EXACOPY_MANAGED_SYNC_CLI_FD"], "11")
            self.assertEqual(env["EXACOPY_MANAGED_SYNC_CLI_SHA256"], digest)
            self.assertEqual(env["EXACOPY_MANAGED_SYNC_CLI_MODE"], "493")
            self.assertEqual(facts, {"dev": 8, "ino": 9, "mode": 493, "size": len(elf), "sha256": digest})
            changed = elf[:-1] + b"x"
            read.side_effect = lambda _fd, size, offset: changed[offset:offset + size]
            self.assertNotEqual(run.held_managed_image(path, fd), observed)
            read.side_effect = lambda _fd, size, offset: (elf + b"x")[offset:offset + size]
            with self.assertRaisesRegex(ValueError, "changed during hashed observation"):
                run.held_managed_image(path, fd)
            named.return_value = SimpleNamespace(**(metadata | {"st_ino": 10}))
            with self.assertRaisesRegex(ValueError, "identity or size differs"):
                run.held_managed_image(path, fd)
            named.return_value = held.return_value = SimpleNamespace(
                **(metadata | {"st_size": run.MANAGED_CLI_LIMIT + 1})
            )
            read.reset_mock()
            with self.assertRaisesRegex(ValueError, "identity or size differs"):
                run.held_managed_image(path, fd, run.MANAGED_CLI_LIMIT)
            named.return_value = held.return_value = SimpleNamespace(**(metadata | {"st_nlink": 0}))
            with self.assertRaisesRegex(ValueError, "identity or size differs"):
                run.held_managed_image(path, fd, run.MANAGED_CLI_LIMIT)
            for mode in (0o100, 0o400, 0o775, 0o757, 0o4755, 0o2755, 0o1755):
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "identity or size differs"):
                    named.return_value = held.return_value = SimpleNamespace(
                        **(metadata | {"st_mode": stat.S_IFREG | mode})
                    )
                    run.held_managed_image(path, fd, run.MANAGED_CLI_LIMIT)
            read.assert_not_called()

    def test_managed_execute_inherits_only_the_selected_cli_and_rechecks_its_digest(self):
        binary, cli = Path("/private/test-harness"), Path("/private/exacopy")
        elf = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00"
        image = SimpleNamespace(read=lambda _size: elf, fileno=lambda: 10)
        node = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_size=20)
        harness = ((8, 10, stat.S_IFREG | 0o700, 1000, 1000, 1, 20, 1, 2), "b" * 64)
        observed_cli = ((8, 11, stat.S_IFREG | 0o755, 1000, 1000, 2, 20, 1, 2), self.cli_sha256)

        def launch(_evidence, label, _args, **options):
            if label != "run":
                self.assertEqual(options["held"], (10,))
                return f"{run.MANAGED.case}: test"
            self.assertEqual(options["held"], (10, 11))
            self.assertEqual(options["executable"], "/proc/self/fd/10")
            self.assertEqual(options["env"]["EXACOPY_MANAGED_SYNC_CLI_FD"], "11")
            self.assertEqual(options["env"]["EXACOPY_MANAGED_SYNC_CLI_SHA256"], self.cli_sha256)
            self.assertEqual(options["env"]["EXACOPY_MANAGED_SYNC_CLI_MODE"], "493")
            return "transcript", 0

        changed_mode = (*observed_cli[0][:2], stat.S_IFREG | 0o700, *observed_cli[0][3:])
        for final_cli in (observed_cli, (observed_cli[0], "0" * 64), (changed_mode, self.cli_sha256)):
            with (self.subTest(final_cli=final_cli),
                  patch.object(run.os, "open", side_effect=(10, 11)),
                  patch.object(run.os, "close"),
                  patch.object(run.os, "fdopen") as opened,
                  patch.object(run.os, "fstat", return_value=node),
                  patch.object(run.os, "fchmod") as chmod,
                  patch.object(run, "held_managed_image", side_effect=(
                      harness, harness, observed_cli, final_cli, harness,
                  )),
                  patch.object(run, "command", side_effect=launch),
                  patch.object(run, "checked_managed_result", return_value={"outcome": "passed"}) as result):
                opened.return_value.__enter__.return_value = image
                report = {}
                args = (Path("/evidence"), binary, {}, {}, report, run.MANAGED, {}, cli)
                if final_cli == observed_cli:
                    run.execute(*args)
                    result.assert_called_once_with("transcript", 0, {}, {}, self.cli_sha256)
                    self.assertEqual(report["cli_executable"]["sha256"], self.cli_sha256)
                else:
                    with self.assertRaisesRegex(ValueError, "changed after execution"):
                        run.execute(*args)
                    result.assert_not_called()
                chmod.assert_not_called()

    def test_success_binds_admission_facts_and_selected_control_inventory(self):
        facts, anchors = self.observations()
        success = self.output(
            "passed boot=00000000-0000-0000-0000-000000000001 mnt_ns=0:4:10 user_ns=0:4:11 "
            "mount=25 unique_mount=5021 anchor=8:1:5 anchor_left=8:1:6 anchor_right=8:1:7 "
            "live=8:1:8 live_left=8:1:9 live_right=8:1:10 controls=8 "
            f"cli_controls=15 cli_sha256={self.cli_sha256} cleanup=verified",
        )
        result = run.checked_managed_result(success, 0, facts, anchors, self.cli_sha256)
        self.assertEqual((result["outcome"], result["feature"], result["controls"]),
                         ("passed", run.MANAGED.required_feature, 8))
        self.assertEqual((result["cli_controls"], result["cli_sha256"]), (15, self.cli_sha256))
        for old, new in (
            ("000000000001", "000000000002"), ("mnt_ns=0:4:10", "mnt_ns=0:4:9"),
            ("user_ns=0:4:11", "user_ns=0:4:9"), ("mount=25", "mount=24"),
            ("unique_mount=5021", "unique_mount=5022"), ("anchor=8:1:5", "anchor=8:1:6"),
            ("anchor_left=8:1:6", "anchor_left=8:1:7"), ("anchor_right=8:1:7", "anchor_right=8:1:6"),
            ("live=8:1:8", "live=8:2:8"), ("live_left=8:1:9", "live_left=8:1:6"),
            ("live_right=8:1:10", "live_right=8:1:18446744073709551616"),
            ("cli_controls=15", "cli_controls=14"),
            (f"cli_sha256={self.cli_sha256}", f"cli_sha256={'0' * 64}"),
            ("controls=8", "controls=7"), (" controls=8", ""), (" live_left=8:1:9", ""),
            ("cleanup=verified", "cleanup=unconfirmed"),
            ("running 1 test", "running 0 tests"), (run.MANAGED.case, "unrelated_case"),
            ("0 ignored", "1 ignored"),
        ):
            with self.subTest(old=old), self.assertRaises(ValueError):
                run.checked_managed_result(success.replace(old, new), 0, facts, anchors, self.cli_sha256)
        for output, code in ((success, 101), (success + success, 0)):
            with self.assertRaises(ValueError):
                run.checked_managed_result(output, code, facts, anchors, self.cli_sha256)

    def test_unsupported_fixture_is_typed_nonpassing(self):
        facts, anchors = self.observations()
        for reason in ("statmount-attributes-unavailable", "idmapped-history-mount"):
            blocked = self.output(f"blocked reason={reason}", blocked=True)
            result = run.checked_managed_result(blocked, 101, facts, anchors, self.cli_sha256)
            self.assertEqual((result["outcome"], result["reason"]), ("blocked", reason))
            for output, code in ((blocked, 0), (blocked, 77),
                                 (blocked.replace(reason, "other"), 101),
                                 (blocked.replace("1 failed", "0 failed"), 101)):
                with self.assertRaises(ValueError):
                    run.checked_managed_result(output, code, facts, anchors, self.cli_sha256)

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

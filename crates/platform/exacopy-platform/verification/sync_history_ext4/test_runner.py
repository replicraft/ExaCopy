"""Portable source-level qualification controls without building or mounting."""

import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import run


class Controls(unittest.TestCase):
    def test_manifest_matches_exact_integration_profile(self):
        self.assertRegex(run.manifest_digest(), r"^[0-9a-f]{64}$")

    def test_requires_whole_writable_ext4_and_exact_device(self):
        device = os.makedev(8, 1)
        row = b"33 12 8:1 / / rw,relatime - ext4 /dev/test rw,errors=remount-ro"
        self.assertEqual(run.mount_row(row, 33, device), row)
        for wrong in (row.replace(b"ext4", b"tmpfs"), row.replace(b" / / ", b" /subtree / "),
                      row.replace(b" rw", b" ro"), row.replace(b"8:1", b"8:2"),
                      row + b"\n" + row):
            with self.subTest(wrong=wrong), self.assertRaises(run.Blocked):
                run.mount_row(wrong, 33, device)

    def test_requires_exact_integration_artifact(self):
        target = Path("/private/test-target")
        path = target / "program"
        event = {
            "reason": "compiler-artifact", "executable": str(path), "profile": {"test": True},
            "manifest_path": str(run.PACKAGE / "Cargo.toml"),
            "target": {"name": run.TEST, "kind": ["test"],
                       "src_path": str(run.PACKAGE / "tests" / f"{run.TEST}.rs")},
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(run.artifact(json.dumps(event), target), path)
            for field, value in (("kind", ["lib"]), ("name", "unrelated"), ("src_path", "/wrong")):
                changed = copy.deepcopy(event)
                changed["target"][field] = value
                with self.assertRaises(ValueError):
                    run.artifact(json.dumps(changed), target)
            with self.assertRaises(ValueError):
                run.artifact("\n".join([json.dumps(event)] * 2), target)

    def test_requires_exact_executed_result_and_native_identity(self):
        facts = {
            "boot": "00000000-0000-0000-0000-000000000001", "mount": 25,
            "mount_namespace": "0:10", "user_namespace": "0:11", "parent": "8:5", "unique_mount": 5021,
        }
        marker = (f"{run.MARKER}schema_version=1 boot={facts['boot']} mount_namespace=0:10 "
                  "user_namespace=0:11 mount=25 unique_mount=5021 parent=8:6 left=8:7 "
                  "right=8:8 cleanup=verified_absent")
        success = (f"test {run.CASE} ... \n{marker}\nok\n"
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.assertEqual(run.checked_result(success, facts)["left"], "8:7")
        for wrong in (success.replace("1 passed", "0 passed"),
                      success.replace("0 ignored", "1 ignored"),
                      success.replace("user_namespace=0:11", "user_namespace=0:12"),
                      success.replace("right=8:8", "right=8:7"),
                      success.replace("right=8:8", "right=9:8"),
                      success.replace("cleanup=verified_absent", "cleanup=unknown"),
                      success.replace("unique_mount=5021", "unique_mount=5022"),
                      success + marker + "\n", success.replace(marker + "\n", "")):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                run.checked_result(wrong, facts)


if __name__ == "__main__":
    unittest.main(verbosity=2)

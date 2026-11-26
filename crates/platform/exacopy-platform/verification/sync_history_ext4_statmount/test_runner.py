"""Portable controls for the exact statmount evidence contract."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sync_history_ext4"))
import run


class Controls(unittest.TestCase):
    def test_statmount_requires_exact_registered_build_feature(self):
        profile = run.STATMOUNT
        self.assertRegex(run.manifest_digest(profile), r"^[0-9a-f]{64}$")
        target = Path("/private/test-target")
        event = {
            "reason": "compiler-artifact", "executable": str(target / "program"),
            "profile": {"test": True}, "manifest_path": str(run.PACKAGE / "Cargo.toml"),
            "target": {"name": profile.test, "kind": ["test"],
                       "src_path": str(run.PACKAGE / "tests" / f"{profile.test}.rs")},
            "features": [profile.required_feature],
        }
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda self, **_: self):
            self.assertEqual(run.artifact(json.dumps(event), target, profile), target / "program")
            for features in (None, [], ["unrelated"], [profile.required_feature, "unrelated"]):
                wrong = {**event, "features": features}
                with self.subTest(features=features), self.assertRaises(ValueError):
                    run.artifact(json.dumps(wrong), target, profile)
            with self.assertRaises(ValueError):
                run.artifact(json.dumps(event), target)

    def test_statmount_checks_typed_blockage_and_independent_positive_identity(self):
        profile = run.STATMOUNT
        facts = {
            "boot": "00000000-0000-0000-0000-000000000001", "mount": 25,
            "mount_namespace": "0:10", "user_namespace": "0:11", "parent": "8:5", "unique_mount": 5021,
        }
        sides = {"left": "8:6", "right": "8:7"}
        header = f"test {profile.case} ... \n"
        marker = (f"{run.STATMOUNT_MARKER}schema_version=1 outcome=passed feature={profile.required_feature} "
                  f"boot={facts['boot']} mount_namespace=0:10 user_namespace=0:11 mount=25 "
                  "unique_mount=5021 parent=8:5 left=8:6 right=8:7 idmap=clear")
        success = (header + marker + "\nok\n"
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.assertEqual(run.checked_statmount_result(success, 0, facts, sides)["outcome"], "passed")
        for wrong in (success.replace("parent=8:5", "parent=8:8"),
                      success.replace("right=8:7", "right=8:6"),
                      success.replace("idmap=clear", "idmap=unknown"),
                      success.replace(profile.required_feature, "wrong"), success + marker + "\n"):
            with self.assertRaises(ValueError):
                run.checked_statmount_result(wrong, 0, facts, sides)

        blocked_marker = (f"{run.STATMOUNT_MARKER}schema_version=1 outcome=blocked "
                          f"feature={profile.required_feature} reason=unsupported_mount_attributes")
        blocked = (header + blocked_marker + "\nFAILED\n"
                   "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
        self.assertEqual(run.checked_statmount_result(blocked, 101, facts, sides)["outcome"], "blocked")
        denied = blocked.replace("unsupported_mount_attributes", "permission_denied")
        observed = run.checked_statmount_result(denied, 101, facts, sides)
        self.assertEqual((observed["outcome"], observed["reason"]), ("blocked", "permission_denied"))
        for output, code in ((blocked, 0), (blocked, 1), (success, 101), (denied, 0), (denied, 1),
                             (blocked.replace("unsupported_mount_attributes", "unknown"), 101),
                             (blocked.replace("1 failed", "0 failed"), 101)):
            with self.assertRaises(ValueError):
                run.checked_statmount_result(output, code, facts, sides)


if __name__ == "__main__":
    unittest.main(verbosity=2)

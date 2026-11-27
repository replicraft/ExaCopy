"""Source-level controls for the owned candidate download directory."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name("remote_commissioning_candidate_input.sh").resolve()


class CandidateInputControls(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="exacopy-candidate-input-control-")
        self.addCleanup(scratch.cleanup)
        self.parent = Path(scratch.name).resolve()
        self.input = self.parent / "exacopy-preview-candidate-input"
        self.marker = self.parent / "exacopy-preview-candidate-input.pending"
        self.report = self.parent / "exacopy-preview-candidate-cleanup.txt"

    def call(self, operation, **changes):
        env = {
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(self.parent),
            "GITHUB_JOB": "preview-direct",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "ARTIFACT_ID": "456",
            "CANDIDATE_RUN_ATTEMPT": "2",
        }
        return subprocess.run(
            ["bash", str(HELPER), operation],
            env=env | changes, capture_output=True, text=True, timeout=5,
        )

    def test_stage_refuses_before_creating_owned_path(self):
        for changes in (
            {"GITHUB_JOB": "direct"},
            {"CANDIDATE_RUN_ATTEMPT": "1"},
            {"ARTIFACT_ID": ""},
            {"ARTIFACT_ID": "456,789"},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.call("stage", **changes).returncode, 0)
                self.assertEqual(list(self.parent.iterdir()), [])

    def test_cleanup_preserves_an_unowned_directory(self):
        self.input.mkdir()
        sentinel = self.input / "sentinel"
        sentinel.write_text("unowned", encoding="ascii")
        self.assertNotEqual(self.call("cleanup").returncode, 0)
        self.assertEqual(sentinel.read_text(encoding="ascii"), "unowned")
        self.assertIn("reason=input-identity-unavailable", self.report.read_text(encoding="ascii"))

    @unittest.skipUnless(sys.platform == "linux", "runner cleanup uses GNU stat and rm")
    def test_cleanup_removes_only_the_owned_input(self):
        result = self.call("stage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.input.stat().st_mode & 0o777, 0o700)
        outside = self.parent / "outside"
        outside.write_text("preserve", encoding="ascii")
        (self.input / "archive").write_bytes(b"fixture archive")
        (self.input / "external-link").symlink_to(outside)
        result = self.call("cleanup")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.parent.iterdir()), [outside])
        self.assertEqual(outside.read_text(encoding="ascii"), "preserve")

    @unittest.skipUnless(sys.platform == "linux", "runner cleanup uses GNU stat and rm")
    def test_cleanup_blocks_after_input_identity_changes(self):
        result = self.call("stage")
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.parent / "original-input"
        self.input.rename(original)
        self.input.mkdir(mode=0o700)
        self.assertNotEqual(self.call("cleanup").returncode, 0)
        self.assertTrue(self.input.is_dir())
        self.assertTrue(original.is_dir())
        self.assertTrue(self.marker.is_file())
        self.assertIn("reason=input-identity-changed", self.report.read_text(encoding="ascii"))

    @unittest.skipUnless(sys.platform == "linux", "runner cleanup uses GNU stat and rm")
    def test_cleanup_keeps_input_when_fixture_cleanup_is_unconfirmed(self):
        env = {"GITHUB_JOB": "embedded"}
        result = self.call("stage", **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        pending = self.parent / "exacopy-wireguard-commissioning/report/cleanup-unconfirmed.json"
        pending.parent.mkdir(parents=True)
        pending.write_text("{}", encoding="ascii")
        self.assertNotEqual(self.call("cleanup", **env).returncode, 0)
        self.assertTrue(self.input.is_dir())
        self.assertTrue(self.marker.is_file())
        self.assertIn("reason=fixture-cleanup-unconfirmed", self.report.read_text(encoding="ascii"))


if __name__ == "__main__":
    unittest.main()

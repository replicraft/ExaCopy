"""Non-publishing controls for release workflow inputs and run identity."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release_candidate as candidate
import release_signed as signed


class ReleaseControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        app = root / "apps/exacopy-cli"
        app.mkdir(parents=True)
        (app / "Cargo.toml").write_text(
            '[package]\nname = "exacopy-cli"\nversion.workspace = true\n', encoding="utf-8",
        )
        (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n', encoding="utf-8")
        (root / "Cargo.lock").write_text(
            '[[package]]\nname = "exacopy-cli"\nversion = "0.1.0"\n', encoding="utf-8",
        )
        self.root = root
        self.commit = "a" * 40
        self.ref = "refs/tags/v0.1.0"
        source = patch.object(candidate, "ROOT", root)
        source.start()
        self.addCleanup(source.stop)

    def clean_git(self, *command):
        if command[0] == "rev-parse":
            return self.commit
        if command[0] == "status":
            return ""
        self.fail(f"unexpected Git operation: {command}")

    def test_clean_canonical_tag_agrees_with_all_cargo_versions(self):
        with patch.object(candidate, "git", self.clean_git):
            self.assertEqual(candidate.check_source(self.ref, self.commit), "0.1.0")
            (self.root / "Cargo.lock").write_text(
                '[[package]]\nname = "exacopy-cli"\nversion = "0.1.1"\n', encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "locked package"):
                candidate.check_source(self.ref, self.commit)

    def test_refuses_invalid_tags_before_git(self):
        with patch.object(candidate, "git", side_effect=AssertionError("called Git")):
            for ref in ("refs/heads/v0.1.0", "refs/tags/v00.1.0", "refs/tags/v0.1.0-rc1", "refs/tags/v1000000.0.0"):
                with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "canonical"):
                    candidate.check_source(ref, self.commit)
            with self.assertRaisesRegex(ValueError, "complete lowercase"):
                candidate.check_source(self.ref, self.commit[:20])

    def test_refuses_moved_tag_or_dirty_source(self):
        with patch.object(candidate, "git", side_effect=[self.commit, "b" * 40]):
            with self.assertRaisesRegex(ValueError, "resolve"):
                candidate.check_source(self.ref, self.commit)
        with patch.object(candidate, "git", side_effect=[self.commit, self.commit, "?? fixture"]):
            with self.assertRaisesRegex(ValueError, "clean source"):
                candidate.check_source(self.ref, self.commit)

    def test_production_key_requires_material_and_exact_trust_pin(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "production signing requires"):
                signed.production_key(self.root)
        with patch.dict(os.environ, {
            "EXACOPY_RELEASE_PRIVATE_KEY_PEM": "invalid fixture",
            "EXACOPY_RELEASE_PUBLISHER_CERT_DER_B64": "AA==",
            "EXACOPY_RELEASE_PUBLISHER_SHA256": "0" * 64,
        }, clear=True):
            with self.assertRaisesRegex(ValueError, "independently approved pin"):
                signed.production_key(self.root)

    def test_production_requires_protected_tag_and_exact_ci_success(self):
        identity = self.commit, self.ref.removeprefix("refs/tags/"), "0.1.0"
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "protected"):
                signed.required_success(identity)
        latest = {"head_sha": self.commit, "head_branch": "main", "event": "push",
                  "status": "completed", "conclusion": "success"}
        with patch.dict(os.environ, {"GITHUB_REF_PROTECTED": "true", "GITHUB_REPOSITORY": "replicraft/ExaCopy"}):
            with patch.object(signed.subprocess, "check_output", return_value=json.dumps({"workflow_runs": [latest]})):
                signed.required_success(identity)
            latest["conclusion"] = "failure"
            with patch.object(signed.subprocess, "check_output", return_value=json.dumps({"workflow_runs": [latest]})):
                with self.assertRaisesRegex(ValueError, "successful push-to-main"):
                    signed.required_success(identity)

    def test_immutability_gate_rejects_missing_token_and_false_setting(self):
        with self.assertRaisesRegex(ValueError, "EXACOPY_IMMUTABILITY_READ_TOKEN"):
            signed.require_immutability("replicraft/ExaCopy", "")
        with patch.object(signed.subprocess, "check_output", return_value='{"enabled": false}'):
            with self.assertRaisesRegex(ValueError, "must be enabled"):
                signed.require_immutability("replicraft/ExaCopy", "fixture")


if __name__ == "__main__":
    unittest.main()

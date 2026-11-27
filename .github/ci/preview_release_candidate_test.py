"""Portable checks for a one-shot real-main preview request and its producer."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import preview_release_candidate as preview


class MainPreviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "apps/exacopy-cli").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
        (self.root / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "exacopy-cli"\nversion = "0.1.0"\n')
        (self.root / "apps/exacopy-cli/Cargo.toml").write_text('[package]\nname = "exacopy-cli"\nversion.workspace = true\n')
        self.git("add", "Cargo.toml", "Cargo.lock", "apps/exacopy-cli/Cargo.toml")
        self.git("commit", "-qm", "Synthetic prior source")
        fixture = {
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": preview.provider_b.WORKFLOW_REF,
        }
        self.scope = patch.dict(os.environ, fixture)
        self.scope.start()
        self.addCleanup(self.scope.stop)
        hosted = patch.object(preview.provider_b, "hosted_scope")
        hosted.start()
        self.addCleanup(hosted.stop)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", self.root, *args], text=True).strip()

    def commit_request(self, contents):
        path = self.root / preview.REQUEST
        if contents is None:
            self.git("rm", preview.REQUEST)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
            self.git("add", preview.REQUEST)
        self.git("commit", "-qm", "Synthetic request change")

    def ask(self):
        revision = self.git("rev-parse", "HEAD")
        with contextlib.chdir(self.root), patch.object(preview.release_candidate, "ROOT", self.root), patch.dict(
            os.environ, {"GITHUB_SHA": revision}
        ):
            return preview.plan()

    def test_request_is_selected_only_on_the_tip_change(self):
        selected = {**preview.REQUEST_FIELDS, "nonce": "ab" * 16}
        self.commit_request(json.dumps(selected))
        result = self.ask()
        self.assertEqual(result["status"], "requested")
        self.assertEqual(result["request"], selected)
        self.assertEqual(result["source"]["revision"], self.git("rev-parse", "HEAD"))
        self.assertEqual(result["source"]["revision"], result["workflow"]["sha"])
        self.assertEqual(result["workflow"]["run_attempt"], "1")
        self.git("commit", "--allow-empty", "-qm", "Unrelated subsequent revision")
        self.assertEqual(self.ask(), {"schema": preview.PLAN_SCHEMA, "status": "not-requested"})

    def test_changed_missing_malformed_or_duplicate_request_refuses(self):
        self.commit_request("{}")
        with self.assertRaisesRegex(ValueError, "invalid closed"):
            self.ask()
        self.commit_request('{"nonce": "duplicate", "nonce": "duplicate"}')
        with self.assertRaisesRegex(ValueError, "repeated deployment field"):
            self.ask()
        self.commit_request(None)
        with self.assertRaisesRegex(ValueError, "tracked regular file"):
            self.ask()

    def test_selected_rerun_refuses_and_ordinary_rerun_is_unchanged(self):
        self.commit_request(json.dumps({**preview.REQUEST_FIELDS, "nonce": "ab" * 16}))
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.assertRaisesRegex(ValueError, "first hosted run attempt"):
                self.ask()
            self.git("commit", "--allow-empty", "-qm", "Synthetic unrelated revision")
            self.assertEqual(self.ask()["status"], "not-requested")

    def test_mode_only_change_cannot_reactivate_request(self):
        self.commit_request(json.dumps({**preview.REQUEST_FIELDS, "nonce": "ab" * 16}))
        self.git("config", "core.filemode", "true")
        request = self.root / preview.REQUEST
        request.chmod(0o755)
        self.git("add", preview.REQUEST)
        self.git("commit", "-qm", "Synthetic executable mode")
        request.chmod(0o644)
        self.git("add", preview.REQUEST)
        self.git("commit", "-qm", "Synthetic regular mode")
        with self.assertRaisesRegex(ValueError, "must change the committed policy contents"):
            self.ask()

    def test_dirty_source_and_foreign_workflow_refuse(self):
        self.git("commit", "--allow-empty", "-qm", "Synthetic clean tip")
        with patch.object(preview.provider_b, "hosted_scope", side_effect=preview.provider_b.Blocked("foreign")):
            with self.assertRaisesRegex(preview.provider_b.Blocked, "foreign"):
                self.ask()
        (self.root / "unexpected").write_text("dirty checkout")
        with self.assertRaisesRegex(ValueError, "pristine checkout"):
            self.ask()

    def test_invalid_plan_emits_terminal_status_and_nonzero(self):
        output = self.root / "invalid.json"
        with patch.object(preview, "plan", side_effect=ValueError("bad input")), patch.object(
            sys, "argv", ["fixture", "plan", "--output", str(output)]
        ), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as failure:
                preview.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(json.loads(output.read_bytes()), {"schema": preview.PLAN_SCHEMA, "status": "invalid"})

    def test_failed_build_admission_never_calls_cargo(self):
        plan = self.root / "planned.json"
        plan.write_text(json.dumps({"status": "requested", "wrong": True}))
        args = ["fixture", "build", "--plan", str(plan), "--output", str(self.root / "out"), "--evidence", str(self.root / "log")]
        with patch.object(preview, "plan", return_value={"status": "requested", "correct": True}), patch.object(
            sys, "argv", args
        ), patch.object(preview.packaging, "build") as builder, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as failure:
                preview.main()
            self.assertEqual(failure.exception.code, 1)
            builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()

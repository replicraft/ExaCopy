"""Source admission and unsigned preview packaging controls without a Rust build."""

from pathlib import Path
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release_candidate
import testing_remote_asset as preview

COMMIT = "a" * 40


class TestingRemoteAssetTests(unittest.TestCase):
    def test_preview_ref_is_admitted_only_by_the_unsigned_entrypoint(self):
        with self.assertRaisesRegex(ValueError, "canonical vMAJOR.MINOR.PATCH"):
            release_candidate.check_source(preview.PREVIEW_REF, COMMIT)
        with patch.object(release_candidate, "check_source_version", return_value="0.1.0") as check:
            self.assertEqual(preview.check_source(preview.PREVIEW_REF, COMMIT), ("0.1.0", preview.PREVIEW_TAG))
            check.assert_called_once_with(preview.PREVIEW_REF, COMMIT, "0.1.0")

    def test_other_preview_refs_and_branch_ref_are_refused(self):
        for ref in ("refs/tags/v0.1.0-preview.1", "refs/tags/v0.1.0-preview.3", "refs/heads/main"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "canonical"):
                preview.check_source(ref, COMMIT)

    def test_preview_uses_real_clean_source_and_locked_cli_version_checks(self):
        for git, error in (
            (["b" * 40], "checkout HEAD"),
            ([COMMIT, "b" * 40], "the tag must both resolve"),
            ([COMMIT, COMMIT, "?? changed"], "clean source checkout"),
        ):
            with self.subTest(git=git), patch.object(release_candidate, "git", side_effect=git):
                with self.assertRaisesRegex(ValueError, error):
                    preview.check_source(preview.PREVIEW_REF, COMMIT)
        with patch.object(release_candidate, "git", side_effect=[COMMIT, COMMIT, ""]):
            self.assertEqual(preview.check_source(preview.PREVIEW_REF, COMMIT), ("0.1.0", preview.PREVIEW_TAG))
        with self.assertRaisesRegex(ValueError, "hexadecimal object ID"):
            preview.check_source(preview.PREVIEW_REF, "aaa")

    def test_archive_is_deterministic_and_contains_only_expected_members(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar.gz"
            replay = Path(directory) / "replay.tar.gz"
            preview.write_archive(first, b"fixture executable", b"fixture license")
            preview.write_archive(replay, b"fixture executable", b"fixture license")
            self.assertEqual(first.read_bytes(), replay.read_bytes())
            self.assertEqual(first.read_bytes()[4:8], bytes(4))
            with tarfile.open(first) as archive:
                self.assertEqual([(m.name, m.mode) for m in archive], [("exacopy", 0o755), ("LICENSE", 0o644)])
                self.assertEqual(archive.extractfile("exacopy").read(), b"fixture executable")

    def test_candidate_build_cleanup_retains_only_uncertain_target(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence"
            with preview.build_target(evidence, {}) as clean:
                self.assertTrue(clean.is_dir())
            self.assertFalse(clean.exists())
            with self.assertRaises(ValueError):
                with preview.build_target(evidence, {}) as failed:
                    raise ValueError("fixture build failed with confirmed cleanup")
            self.assertFalse(failed.exists())
            with self.assertRaises(preview.native.CleanupUnconfirmed):
                with preview.build_target(evidence, {}) as retained:
                    raise preview.native.CleanupUnconfirmed("fixture cleanup unconfirmed")
            self.assertTrue(retained.is_dir())
            marker = json.loads((evidence / "cleanup-unconfirmed.json").read_bytes())
            self.assertEqual(marker, {"target": str(retained), "status": "cleanup-unconfirmed"})

    def test_archive_readback_binds_both_members_to_one_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "preview.tar.gz"
            preview.write_archive(archive, b"fixture executable", b"fixture license")
            record = preview.verify_archive(archive, b"fixture executable", b"fixture license")
            self.assertEqual(record, {
                "name": archive.name, "sha256": preview.digest(archive), "size": archive.stat().st_size,
            })
            self.assertEqual(preview.read_archive(archive, len(b"fixture executable"), b"fixture license"),
                             (record, b"fixture executable"))
            for binary, license_text in (
                (b"swapped executable", b"fixture license"), (b"fixture executable", b"swapped license"),
            ):
                with self.assertRaisesRegex(ValueError, "member differs"):
                    preview.verify_archive(archive, binary, license_text)

    def test_archive_readback_refuses_trailing_stream_and_corrupted_gzip_footer(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "preview.tar.gz"
            binary, license_text = b"fixture executable", b"fixture license"
            preview.write_archive(archive, binary, license_text)
            canonical = archive.read_bytes()
            for invalid in (canonical + b"x", canonical * 2, canonical[:-1] + b"\xff"):
                with self.subTest(size=len(invalid)), self.assertRaisesRegex(ValueError, "gzip stream"):
                    archive.write_bytes(invalid)
                    preview.verify_archive(archive, binary, license_text)

    def test_receipts_bind_single_archive_build_features_and_exact_cargo_metadata_query(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            evidence = temp / "evidence"
            evidence.mkdir()
            executable = temp / "release/exacopy"
            executable.parent.mkdir()
            payload = b"fixture executable"
            executable.write_bytes(payload)
            binary = temp / "verified-exacopy"
            binary.write_bytes(payload)
            archive = temp / "preview.tar.gz"
            preview.write_archive(archive, payload, b"fixture license")
            record = preview.verify_archive(archive, payload, b"fixture license")
            features = ["experimental-ssh-capture", preview.ROUTE_FEATURE]
            root = "path+file:///fixture/apps/exacopy-cli#0.1.0"
            log = evidence / "build.log"
            log.write_text("Compiling fixture\n" + json.dumps({
                "reason": "compiler-artifact", "package_id": root, "executable": str(executable),
                "target": {"name": "exacopy", "kind": ["bin"]}, "features": features,
            }) + "\n")
            observed = {
                "compiled_features": features, "build_log_sha256": preview.digest(log),
                "build_sha256": preview.digest(binary), "build_size": len(payload), "argv": ["cargo", "build"],
                "source_after": {"revision": COMMIT, "git_tree": "b" * 40, "lock_sha256": "c" * 64},
            }
            manifest = evidence / "result.json"
            manifest.write_text(json.dumps(observed))
            metadata = {"packages": [{
                "id": root, "name": "exacopy-cli", "version": "0.1.0", "source": None, "license": "Apache-2.0",
            }], "workspace_members": [root]}
            workflow = {
                "GITHUB_WORKFLOW_REF": "workflow", "GITHUB_WORKFLOW_SHA": COMMIT,
                "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            }
            with patch.dict(os.environ, workflow), patch.object(
                release_candidate.sbom_release, "output", return_value=json.dumps(metadata)
            ) as cargo:
                preview.write_preview_receipts(temp, evidence, record, binary, observed, manifest, {}, {})
                self.assertEqual(cargo.call_args.args[-3:], (
                    "--no-default-features", "--features", f"exacopy-cli/{preview.ROUTE_FEATURE}",
                ))
            receipt = json.loads((temp / "build-provenance-experimental-ssh-wireguard.json").read_bytes())
            self.assertEqual(receipt["tag"], preview.PREVIEW_TAG)
            self.assertEqual(receipt["workspace_version"], preview.PREVIEW_BASE)
            self.assertEqual(receipt["archive"]["sha256"], preview.digest(archive))
            self.assertEqual(receipt["binary"]["sha256"], preview.digest(binary))
            self.assertEqual(receipt["exact_elf_campaigns"], "pending")
            log.write_bytes(log.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "transcript changed"):
                preview.write_preview_receipts(temp, evidence, record, binary, observed, manifest, {}, {})

    def test_smoke_matches_exact_reported_version_and_expected_route_help(self):
        outputs = ["exacopy 0.1.0\n", "Usage: exacopy get [OPTIONS]\n", "Usage: exacopy recover remote-resume [OPTIONS]\n"]
        with patch.object(preview.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, output) for output in outputs
        ]):
            preview.smoke("fixture", "0.1.0")
        with patch.object(preview.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "exacopy 0.1.01\n")):
            with self.assertRaisesRegex(ValueError, "expected output"):
                preview.smoke("fixture", "0.1.0")


if __name__ == "__main__":
    unittest.main()

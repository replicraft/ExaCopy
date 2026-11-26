"""Non-publishing controls for release workflow inputs and run identity."""

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import release_candidate as candidate
import release_signed as signed

from release.package import MAX_ARCHIVE, MAX_EXECUTABLE


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

    def test_signing_requires_exact_apfs_build_provenance(self):
        pin = self.root / "specs/dependencies/apfs-source.toml"
        pin.parent.mkdir(parents=True)
        identity = {"commit": "b" * 40, "tree": "c" * 40, "archive_sha256": "d" * 64}
        pin.write_text("".join(f'{key} = "{value}"\n' for key, value in identity.items()), encoding="utf-8")
        target, tag, version = signed.APPLE, "v0.1.0", "0.1.0"
        workspace = self.root / "Cargo.toml"
        workspace.write_bytes(
            b"[workspace]\n" + workspace.read_bytes()
            + f'[workspace.dependencies]\napfs-mounted = {{ path = "{signed.apfs_source.WORKSPACE_PATH}" }}\n'.encode("ascii")
        )
        _, apfs_layout = signed.projected_apfs_manifest(workspace.read_bytes())
        repository = "replicraft/ExaCopy"
        build = self.root / "artifact"
        binary = build / "unsigned-cli/exacopy"
        sbom = build / "build/exacopy.cdx.json"
        binary.parent.mkdir(parents=True)
        sbom.parent.mkdir(parents=True)
        binary.write_bytes(b"test CLI")
        sbom.write_bytes(b"{}")
        apfs_source = {"repository": "https://github.com/pomologie/apfs", **identity}
        provenance = {
            "schema": "exacopy-ci-candidate-build-v1",
            "repository": repository,
            "tag": tag,
            "commit": self.commit,
            "version": version,
            "dirty": False,
            "target": target,
            "profile": "release",
            "features": [],
            "tree": self.commit,
            "lockfile_sha256": signed.sha256(self.root / "Cargo.lock"),
            "apfs_source": apfs_source,
            "apfs_build_layout": apfs_layout,
            "transport_sources": {},
            "runner": {"run_id": "12", "run_attempt": "1"},
            "binary": {"name": binary.name, "size": binary.stat().st_size, "sha256": signed.sha256(binary)},
            "sbom_sha256": signed.sha256(sbom),
        }
        record = sbom.parent / "build-provenance.json"
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": repository, "GITHUB_RUN_ID": "12", "GITHUB_RUN_ATTEMPT": "1",
        }), patch.object(candidate, "git", self.clean_git), patch.object(signed.transport_source, "read_pins", return_value={}):
            record.write_text(json.dumps(provenance))
            self.assertEqual(signed.verified_build(build, target, self.commit, tag, version), (binary, sbom, provenance))
            for field, expected in apfs_source.items():
                with self.subTest(field=field):
                    other = ("e" * len(expected)) if field != "repository" else "https://example.invalid/apfs"
                    altered = provenance | {"apfs_source": apfs_source | {field: other}}
                    record.write_text(json.dumps(altered))
                    with self.assertRaisesRegex(ValueError, "does not match the admitted release source"):
                        signed.verified_build(build, target, self.commit, tag, version)
            for field in ("original_manifest_sha256", "projected_manifest_sha256", "member_path"):
                with self.subTest(layout_field=field):
                    record.write_text(json.dumps(provenance | {"apfs_build_layout": apfs_layout | {field: "wrong"}}))
                    with self.assertRaisesRegex(ValueError, "does not match the admitted release source"):
                        signed.verified_build(build, target, self.commit, tag, version)
            record.write_text(json.dumps({key: value for key, value in provenance.items() if key != "apfs_build_layout"}))
            with self.assertRaisesRegex(ValueError, "does not match the admitted release source"):
                signed.verified_build(build, target, self.commit, tag, version)
            del provenance["apfs_source"]
            record.write_text(json.dumps(provenance))
            with self.assertRaisesRegex(ValueError, "does not match the admitted release source"):
                signed.verified_build(build, target, self.commit, tag, version)

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


    def simulate_publication(self, view_updates=None, draft_updates=None, latest_updates=None,
                             moved_tag=False, expected_error=None, reported_sizes=None):
        repo = "replicraft/ExaCopy"
        tag, version = "v0.1.0", "0.1.0"
        output = self.root / "dist"
        assets, evidence = output / "assets", output / "evidence"
        assets.mkdir(parents=True, exist_ok=True)
        evidence.mkdir(exist_ok=True)
        files = [assets / name for name in candidate.ASSETS.values()]
        files.append(assets / "SHA256SUMS.txt")
        for target in candidate.ASSETS:
            files.extend(evidence / f"exacopy-cli-{target}.{kind}.json" for kind in ("cdx", "provenance"))
        for file in files:
            file.write_text(file.name, encoding="ascii")
        uploaded = [
            {"name": file.name, "digest": f"sha256:{signed.sha256(file)}", "state": "uploaded"}
            for file in files
        ]
        draft_id = 47
        draft_path = f"repos/{repo}/releases/{draft_id}"
        check_tag = ["gh", "api", f"repos/{repo}/git/ref/tags/{tag}", "--jq", ".object.sha"]
        draft_view = ["gh", "release", "view", tag, "--repo", repo,
                      "--json", "databaseId,isDraft,isPrerelease,tagName"]
        publish_id = ["gh", "api", "--method", "PATCH", draft_path, "-F", "draft=false", "-f", "make_latest=true"]
        commands = []

        def query(command, **kwargs):
            del kwargs
            commands.append(command)
            if command == ["gh", "api", f"repos/{repo}/immutable-releases", "-H", "X-GitHub-Api-Version: 2026-03-10"]:
                return '{"enabled": true}'
            if command == ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100"]:
                return "[[]]"
            if command == check_tag:
                return "b" * 40 if moved_tag and commands.count(check_tag) == 2 else self.commit
            if command == draft_view:
                return json.dumps({
                    "databaseId": draft_id, "isDraft": True, "isPrerelease": False, "tagName": tag,
                } | (view_updates or {}))
            if command == ["gh", "api", draft_path]:
                return json.dumps({
                    "id": draft_id, "tag_name": tag, "draft": True, "prerelease": False, "assets": uploaded,
                } | (draft_updates or {}))
            if command == ["gh", "api", f"repos/{repo}/releases/latest"]:
                return json.dumps({
                    "id": draft_id, "tag_name": tag, "draft": False, "prerelease": False,
                    "immutable": True, "assets": uploaded,
                } | (latest_updates or {}))
            self.fail(f"unexpected release query: {command}")

        sha_check = ["sha256sum", "--strict", "-c", "SHA256SUMS.txt"]
        create = ["gh", "release", "create", tag, "--repo", repo, "--verify-tag", "--draft",
                  "--title", f"ExaCopy CLI {version}", "--generate-notes"]
        upload = ["gh", "release", "upload", tag, "--repo", repo, *files]

        def run(command, *, check, **kwargs):
            self.assertTrue(check)
            if command == sha_check:
                self.assertEqual(kwargs["cwd"], assets)
            self.assertIn(command, (sha_check, create, upload, publish_id))
            commands.append(command)

        original_stat = Path.stat

        def stat_with_reported_size(path, *args, **kwargs):
            actual = original_stat(path, *args, **kwargs)
            if reported_sizes is not None and path.name in reported_sizes:
                return SimpleNamespace(st_mode=actual.st_mode, st_size=reported_sizes[path.name])
            return actual

        environment = {"GITHUB_REPOSITORY": repo, "GITHUB_REF": self.ref, "EXACOPY_IMMUTABILITY_READ_TOKEN": "fixture"}
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(candidate, "git", self.clean_git),
            patch.object(Path, "stat", stat_with_reported_size),
            patch.object(signed.subprocess, "run", side_effect=run),
            patch.object(signed.subprocess, "check_output", side_effect=query),
        ):
            if expected_error is None:
                signed.publish(output, (self.commit, tag, version))
            else:
                with self.assertRaisesRegex(ValueError, expected_error):
                    signed.publish(output, (self.commit, tag, version))
        return commands, (create, draft_view, upload, ["gh", "api", draft_path], publish_id)

    def test_uploads_draft_and_promotes_only_verified_database_id(self):
        commands, expected = self.simulate_publication()
        self.assertEqual([entry for entry in commands if entry in expected], list(expected))

    def test_refuses_invalid_draft_view_before_upload(self):
        for updates in (
            {"databaseId": True}, {"databaseId": 0}, {"isDraft": False},
            {"isPrerelease": True}, {"tagName": "v9.9.9"},
        ):
            with self.subTest(updates=updates):
                commands, (_, _, upload, _, promotion) = self.simulate_publication(
                    view_updates=updates, expected_error="exact tagged draft",
                )
                self.assertNotIn(upload, commands)
                self.assertNotIn(promotion, commands)

    def test_retains_draft_if_id_assets_or_tag_change(self):
        for updates, moved_tag in (({"id": 48}, False), ({"assets": []}, False), ({}, True)):
            with self.subTest(updates=updates, moved_tag=moved_tag):
                commands, (_, _, upload, lookup, promotion) = self.simulate_publication(
                    draft_updates=updates, moved_tag=moved_tag, expected_error="preserve the draft",
                )
                self.assertIn(upload, commands)
                self.assertIn(lookup, commands)
                self.assertNotIn(promotion, commands)

    def test_latest_must_report_promoted_database_id(self):
        commands, (_, _, _, _, promotion) = self.simulate_publication(
            latest_updates={"id": 48}, expected_error="latest release verification failed",
        )
        self.assertIn(promotion, commands)


    def test_publication_uses_packaging_limit_for_release_archives(self):
        archive = candidate.ASSETS["x86_64-pc-windows-msvc"]
        commands, (create, _, upload, lookup, promotion) = self.simulate_publication(
            reported_sizes={archive: MAX_ARCHIVE},
        )
        for step in (create, upload, lookup, promotion):
            self.assertIn(step, commands)

        for name, size in ((archive, MAX_ARCHIVE + 1), ("SHA256SUMS.txt", MAX_EXECUTABLE + 1)):
            with self.subTest(name=name):
                commands, (create, _, upload, _, promotion) = self.simulate_publication(
                    reported_sizes={name: size}, expected_error="missing or invalid release input",
                )
                self.assertNotIn(create, commands)
                self.assertNotIn(upload, commands)
                self.assertNotIn(promotion, commands)

    def test_raw_executable_limit_is_unchanged(self):
        binary = self.root / "exacopy.exe"
        binary.touch()
        for extra_bytes, admitted in ((0, True), (1, False)):
            with self.subTest(extra_bytes=extra_bytes), patch.object(
                Path, "stat", return_value=SimpleNamespace(st_mode=0o100644, st_size=MAX_EXECUTABLE + extra_bytes),
            ):
                if admitted:
                    self.assertEqual(signed.checked(binary), binary)
                else:
                    with self.assertRaisesRegex(ValueError, "missing or invalid release input"):
                        signed.checked(binary)


if __name__ == "__main__":
    unittest.main()

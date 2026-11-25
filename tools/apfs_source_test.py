"""Source provenance and isolated sibling layout controls."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from apfs_source import (
    CONSUMER, KEY, MACOS_CFG, MEMBER, NAME, REPOSITORY, WORKSPACE_PATH,
    archive_apfs, dependency_manifest_matches, git_output, provision, read_pin, sibling, verify_consumer,
)
from dependency_review.check import apfs_inputs
from sbom_release import component, extract_sources


class ApfsSourceTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temp).resolve()
        self.source = self.root / "source"
        self.repository = sibling(self.source)
        self.manifest = self.repository / MEMBER / "Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(
            '[package]\nname = "apfs-mounted"\nversion = "0.1.0"\n'
            'repository.workspace = true\nlicense.workspace = true\n', encoding="utf-8",
        )
        (self.repository / "Cargo.toml").write_text(
            f'[workspace]\nmembers = ["{MEMBER.as_posix()}"]\n'
            f'[workspace.package]\nrepository = "{REPOSITORY}"\nlicense = "Apache-2.0"\n',
            encoding="utf-8",
        )
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture")
        self.archive = self.root / "apfs.tar"
        self.git("-c", "tar.umask=0002", "archive", "--format=tar", "--output", str(self.archive), "HEAD")
        self.pin = {
            "commit": git_output(self.repository, "rev-parse", "HEAD"),
            "tree": git_output(self.repository, "rev-parse", "HEAD^{tree}"),
            "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        }

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repository), *args], check=True)

    def test_verified_archive_restores_cargo_sibling_layout_twice(self):
        archive_apfs(self.source, self.pin, self.archive)
        source_archive = self.root / "source.tar"
        subprocess.run([
            "git", "-C", str(self.repository), "archive", "--output", str(source_archive), "HEAD",
        ], check=True)
        for attempt in ("first", "second"):
            source = extract_sources(self.root / attempt, source_archive, self.archive)
            expected_manifest = (source / WORKSPACE_PATH / "Cargo.toml").resolve()
            self.assertEqual(expected_manifest.read_bytes(), self.manifest.read_bytes())
            self.assertNotEqual(expected_manifest, self.manifest)
            self.assertFalse((sibling(source) / ".git").exists())

    def test_rejects_dirty_checkout_and_wrong_revision_tree_or_digest(self):
        for field, message in (
            ("commit", "wrong revision"), ("tree", "tree differs"), ("archive_sha256", "SHA-256 differs"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                archive_apfs(self.source, self.pin | {field: "0" * len(self.pin[field])}, self.archive)
        (self.repository / "untracked.rs").write_text("untracked", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "uncommitted changes"):
            provision(self.source, self.pin)
        (self.repository / "untracked.rs").unlink()
        self.manifest.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "uncommitted changes"):
            archive_apfs(self.source, self.pin, self.archive)

    def test_apfs_identity_requires_exact_manifest_and_compilation_scope(self):
        package = {
            "name": NAME, "version": "0.1.0", "source": None, "manifest_path": str(self.manifest),
            "repository": REPOSITORY, "license": "Apache-2.0", "targets": [{"kind": ["lib"]}],
        }
        macos = "aarch64-apple-darwin"
        parents = {f"{CONSUMER}@0.1.0"}
        record = apfs_inputs(package, self.source, self.pin, macos, parents, set())
        self.assertEqual(record["source"], "local-path")
        self.assertEqual(record["archive_sha256"], self.pin["archive_sha256"])
        self.assertFalse(dependency_manifest_matches(package | {"manifest_path": str(self.root / MEMBER / "Cargo.toml")}, self.source))
        self.assertFalse(dependency_manifest_matches(package | {"source": "git+https://example.invalid"}, self.source))
        for target, edges, features in (
            ("x86_64-unknown-linux-gnu", parents, set()),
            (macos, parents | {"exacopy-model@0.1.0"}, set()),
            (macos, parents, {"default"}),
        ):
            with self.subTest(target=target, edges=edges, features=features):
                with self.assertRaisesRegex(ValueError, f"unexpected source, edges or features for {KEY}"):
                    apfs_inputs(package, self.source, self.pin, target, edges, features)
        external = component(package, {("lib", "")}, None, False, self.pin)
        self.assertEqual(external["bom-ref"], f"local-path:{KEY}#{self.pin['commit']}")
        self.assertIn(
            {"name": "exacopy:source-archive-sha256", "value": self.pin["archive_sha256"]}, external["properties"],
        )

    def test_rejects_malformed_source_pin(self):
        def toml(values):
            return "\n".join(f'{key} = "{value}"' for key, value in values.items())

        self.assertEqual(read_pin(toml(self.pin)), self.pin)
        for values in (
            self.pin | {"commit": "main"},
            self.pin | {"tree": "g" * 40},
            self.pin | {"archive_sha256": "b" * 63},
            self.pin | {"unexpected": "value"},
            {"commit": self.pin["commit"], "tree": self.pin["tree"]},
        ):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "invalid apfs-mounted source pin"):
                read_pin(toml(values))

    def test_workspace_declaration_requires_disabled_defaults_and_target_inheritance(self):
        workspace_dep = {"path": WORKSPACE_PATH, "version": "=0.1.0", "default-features": False}
        root = {"workspace": {"dependencies": {NAME: workspace_dep}}}
        member = {"target": {MACOS_CFG: {"dependencies": {NAME: {"workspace": True}}}}}
        verify_consumer(root, member)
        with self.assertRaisesRegex(ValueError, "macOS dependency table"):
            verify_consumer(root, {"dependencies": {NAME: {"workspace": True}}})
        workspace_dep["default-features"] = True
        with self.assertRaisesRegex(ValueError, "without default features"):
            verify_consumer(root, member)

    def test_workspace_declaration_requires_exact_local_version(self):
        member = {"target": {MACOS_CFG: {"dependencies": {NAME: {"workspace": True}}}}}
        base = {"path": WORKSPACE_PATH, "default-features": False}
        for requirement in ({}, {"version": "0.1.0"}, {"version": "*"}, {"version": "=0.1.1"}):
            with self.subTest(requirement=requirement), self.assertRaisesRegex(ValueError, r"require =0\.1\.0"):
                root = {"workspace": {"dependencies": {NAME: base | requirement}}}
                verify_consumer(root, member)

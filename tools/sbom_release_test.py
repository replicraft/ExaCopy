"""Positive and negative controls for deriving a BOM from Cargo build messages."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from apfs_source import CONSUMER_MANIFEST, MEMBER, REPOSITORY, VERSION, WORKSPACE_PATH, sibling
from sbom_release import (
    APFS_RELEASE_MEMBER, APFS_RELEASE_SOURCE, DARWIN_TARGET, build_environment, build_inputs, component,
    apfs_archive_member, project_release_sources, projected_apfs_manifest, verify_projected_apfs_tree, write_sbom,
)


def artifact(package, target_kind, features, binary=None, *, name=None, manifest=None, source=None):
    return json.dumps({
        "reason": "compiler-artifact",
        "package_id": package,
        "manifest_path": manifest,
        "target": {"name": name or ("exacopy" if binary else package), "kind": [target_kind], "src_path": source},
        "features": features,
        "executable": binary,
    })


class SbomReleaseTests(unittest.TestCase):
    def test_distributed_build_discards_ambient_cpu_flags_and_wrappers(self):
        ambient = {
            "RUSTFLAGS": "-Ctarget-cpu=native",
            "CARGO_ENCODED_RUSTFLAGS": "-Ctarget-feature=+avx2",
            "CFLAGS": "-march=native",
            "CFLAGS_aarch64-apple-darwin": "-mcpu=native",
            "CFLAGS_x86_64_unknown_linux_gnu": "-mavx2",
            "HOST_CXXFLAGS": "-mtune=native",
            "TARGET_ASFLAGS": "-march=native",
            "RUSTC_WRAPPER": "host-wrapper",
            "RUSTC_WORKSPACE_WRAPPER": "workspace-wrapper",
            "PATH": "/trusted/toolchain",
        }
        with patch.dict("os.environ", ambient, clear=True):
            environment = build_environment(Path("/scratch"), "123")
        for key in ambient:
            if "FLAGS" in key and key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
                self.assertNotIn(key, environment)
        self.assertEqual(environment["RUSTFLAGS"], "")
        self.assertEqual(environment["CARGO_ENCODED_RUSTFLAGS"], "--remap-path-prefix=/scratch=/exacopy")
        self.assertEqual(environment["RUSTC_WRAPPER"], "")
        self.assertEqual(environment["RUSTC_WORKSPACE_WRAPPER"], "")
        self.assertEqual(environment["PATH"], "/trusted/toolchain")

    def test_darwin_environment_selects_distribution_deployment_floor(self):
        with patch.dict("os.environ", {"MACOSX_DEPLOYMENT_TARGET": "13.0"}, clear=True):
            self.assertEqual(build_environment(Path("/scratch"), "123", DARWIN_TARGET)["MACOSX_DEPLOYMENT_TARGET"], "14.0")
            self.assertEqual(build_environment(Path("/scratch"), "123")["MACOSX_DEPLOYMENT_TARGET"], "13.0")

    def test_distributed_build_rejects_native_cpu_compiler_commands(self):
        for key, value in (("CC", "clang -march=native"), ("TARGET_CXX", "clang++ -mcpu=native"),
                           ("CC_x86_64_unknown_linux_gnu", "cc -mtune native")):
            with self.subTest(key=key), patch.dict("os.environ", {key: value}, clear=True):
                with self.assertRaisesRegex(ValueError, "host-native CPU"):
                    build_environment(Path("/scratch"), "123")

    def test_build_input_inventory_retains_build_and_library_units(self):
        artifacts = [
            artifact("integrity", "custom-build", ["a"]),
            artifact("integrity", "lib", ["b"]),
            artifact("integrity", "lib", ["a"]),
            artifact("cli", "bin", [], "/target/release/exacopy"),
            '{"reason":"build-script-executed"}',
        ]
        units, executable, _ = build_inputs(artifacts)
        self.assertEqual(executable, ("cli", Path("/target/release/exacopy")))
        self.assertEqual(units["integrity"], {("custom-build", "a"), ("lib", "a"), ("lib", "b")})

    def test_missing_binary_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no CLI executable"):
            build_inputs([artifact("integrity", "custom-build", [])])

    def test_registry_inventory_requires_locked_archive_checksum(self):
        package = {
            "name": "integrity", "version": "1.2.3",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "license": "Apache-2.0",
        }
        units = {("lib", ""), ("custom-build", "a")}
        with self.assertRaisesRegex(ValueError, "checked crates.io source"):
            component(package, units, None, False)
        item = component(package, units, "0" * 64, False)
        self.assertEqual(item["purl"], "pkg:cargo/integrity@1.2.3")
        self.assertEqual(item["licenses"], [{"expression": "Apache-2.0"}])
        self.assertEqual(item["hashes"][0]["content"], "0" * 64)


class ApfsReleaseLayoutTests(unittest.TestCase):
    original = (
        '[workspace]\nmembers = ["apps/cli"]\n[workspace.dependencies]\n'
        f'apfs-mounted = {{ version = "=0.1.0", path = "{WORKSPACE_PATH}", default-features = false }}\n'
        'other = "1"\n'
    ).encode("ascii")

    def stage_archive(self, source):
        archive = source.parent / "apfs.tar"
        with tarfile.open(archive, "w:") as files:
            for relative in MEMBER.parents:
                if relative.parts:
                    entry = tarfile.TarInfo(relative.as_posix())
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o775
                    files.addfile(entry)
            entry = tarfile.TarInfo(MEMBER.as_posix())
            entry.type, entry.mode = tarfile.DIRTYPE, 0o775
            files.addfile(entry)
            contents = b"exact pinned manifest fixture"
            entry = tarfile.TarInfo((MEMBER / "Cargo.toml").as_posix())
            entry.size, entry.mode = len(contents), 0o664
            files.addfile(entry, io.BytesIO(contents))
        with tarfile.open(archive, "r:") as files:
            files.extractall(sibling(source), filter=apfs_archive_member)
        return archive

    def test_projection_moves_only_verified_archive_and_two_manifest_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve() / "source"
            platform = source / CONSUMER_MANIFEST
            platform.parent.mkdir(parents=True)
            platform.write_text("[target.'cfg(target_os = \"macos\")'.dependencies]\napfs-mounted.workspace = true\n")
            base = source / "Cargo.toml"
            base.write_bytes(self.original)
            mounted = sibling(source) / MEMBER / "Cargo.toml"
            archive = self.stage_archive(source)
            self.assertIsNone(project_release_sources(source, "x86_64-unknown-linux-gnu", archive))
            self.assertEqual(base.read_bytes(), self.original)
            self.assertTrue(mounted.is_file())
            reserved = source / APFS_RELEASE_SOURCE.parts[0]
            reserved.mkdir()
            with self.assertRaises(FileExistsError):
                project_release_sources(source, DARWIN_TARGET, archive)
            self.assertEqual(base.read_bytes(), self.original)
            self.assertTrue(mounted.is_file())
            reserved.rmdir()
            layout = project_release_sources(source, DARWIN_TARGET, archive)
            self.assertEqual((source / APFS_RELEASE_MEMBER / "Cargo.toml").read_bytes(), b"exact pinned manifest fixture")
            self.assertFalse(mounted.exists())
            projected = base.read_bytes()
            original_document = tomllib.loads(self.original.decode("ascii"))
            original_document["workspace"]["exclude"] = [APFS_RELEASE_MEMBER.as_posix()]
            original_document["workspace"]["dependencies"]["apfs-mounted"]["path"] = APFS_RELEASE_MEMBER.as_posix()
            self.assertEqual(tomllib.loads(projected.decode("ascii")), original_document)
            self.assertEqual(layout["original_manifest_sha256"], hashlib.sha256(self.original).hexdigest())
            self.assertEqual(layout["projected_manifest_sha256"], hashlib.sha256(projected).hexdigest())

    def test_projection_refuses_changed_edge_or_preselected_exclusion(self):
        for changed in (
            self.original.replace(WORKSPACE_PATH.encode("ascii"), b"alternate"),
            self.original.replace(b"[workspace]\n", b"[workspace]\nexclude = []\n"),
        ):
            with self.subTest(manifest=changed), self.assertRaisesRegex(ValueError, "exact original APFS workspace edge"):
                projected_apfs_manifest(changed)


    def test_projected_archive_rejects_tampered_tree(self):
        for change, decisive in (
            ("extra", "unexpected projected APFS entry"),
            ("missing", "missing projected APFS entry"),
            ("mode", "projected APFS mode differs"),
            ("contents", "projected APFS entry differs"),
            ("symlink", "projected APFS (mode|entry) differs"),
            ("hardlink", "projected APFS entry differs"),
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                source = Path(temp).resolve() / "source"
                archive = self.stage_archive(source)
                projected = source / APFS_RELEASE_SOURCE
                projected.parent.mkdir(parents=True)
                sibling(source).rename(projected)
                verify_projected_apfs_tree(source, archive)
                member = projected / MEMBER / "Cargo.toml"
                if change == "extra":
                    (projected / "extra.toml").touch()
                elif change == "missing":
                    member.unlink()
                elif change == "mode":
                    member.chmod(0o600)
                elif change == "contents":
                    member.write_bytes(b"x" * member.stat().st_size)
                elif change == "symlink":
                    member.unlink()
                    member.symlink_to("absent")
                else:
                    (source / "alias").hardlink_to(member)
                with self.assertRaisesRegex(ValueError, decisive):
                    verify_projected_apfs_tree(source, archive)

    def test_sbom_checks_metadata_and_actual_apfs_compiler_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve()
            (source / "Cargo.lock").write_text("package = []\n")
            _, layout = projected_apfs_manifest(self.original)
            pin = {"commit": "a" * 40, "tree": "b" * 40, "archive_sha256": "c" * 64}
            cli = {"id": "cli", "name": "exacopy-cli", "version": "0.1.0", "source": None, "license": None}
            apfs = {
                "id": "apfs", "name": "apfs-mounted", "version": VERSION, "source": None,
                "repository": REPOSITORY, "license": "Apache-2.0",
            }
            evidence = source / "release.cdx.json"
            expected = source / APFS_RELEASE_MEMBER
            alternate = sibling(source) / MEMBER
            for metadata_member, manifest, entry, error in (
                (expected, expected / "Cargo.toml", expected / "src/lib.rs", None),
                (alternate, expected / "Cargo.toml", expected / "src/lib.rs", "unexpected local Cargo artifact"),
                (expected, alternate / "Cargo.toml", expected / "src/lib.rs", "unexpected APFS compiler artifact origin"),
                (expected, expected / "Cargo.toml", alternate / "src/lib.rs", "unexpected APFS compiler artifact origin"),
                (expected, None, expected / "src/lib.rs", "unexpected APFS compiler artifact origin"),
            ):
                metadata = {
                    "packages": [cli, apfs | {"manifest_path": str(metadata_member / "Cargo.toml")}],
                    "workspace_members": ["cli"],
                }
                units, _, origins = build_inputs([
                    artifact("cli", "bin", [], "/target/exacopy"),
                    artifact("apfs", "lib", [], name="apfs_mounted",
                             manifest=str(manifest) if manifest is not None else None, source=str(entry)),
                ])
                args = (source, {}, evidence, DARWIN_TARGET, "commit", "binary", units, "cli", pin, {}, layout)
                with self.subTest(metadata=metadata_member, manifest=manifest, entry=entry), patch(
                    "sbom_release.output", return_value=json.dumps(metadata),
                ):
                    if error is None:
                        write_sbom(*args, origins=origins)
                        item, = json.loads(evidence.read_bytes())["components"]
                        self.assertEqual(item["bom-ref"], f"local-path:apfs-mounted@{VERSION}#{pin['commit']}")
                    else:
                        with self.assertRaisesRegex(ValueError, error):
                            write_sbom(*args, origins=origins)



class LocalSourceComponentTests(unittest.TestCase):
    def test_local_repair_component_has_no_registry_identity(self):
        pin = {
            "repository": "https://github.com/cloudflare/boringtun",
            "upstream_commit": "a" * 40,
            "registry_archive_sha256": "b" * 64,
            "repair_patch_sha256": "c" * 64,
            "attribution_patch_sha256": "d" * 64,
            "commit": "d" * 40,
            "tree": "e" * 40,
            "archive_sha256": "f" * 64,
        }
        item = component(
            {"name": "boringtun", "version": "0.7.1", "source": None, "license": "BSD-3-Clause"},
            {("lib", "")}, None, False, local_pin=pin,
        )
        self.assertEqual(item["bom-ref"], f"local-path:boringtun@0.7.1#{pin['commit']}")
        self.assertNotIn("purl", item)
        self.assertNotIn("hashes", item)
        self.assertIn(
            {"name": "exacopy:source-archive-sha256", "value": pin["archive_sha256"]}, item["properties"],
        )


if __name__ == "__main__":
    unittest.main()

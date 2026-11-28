from hashlib import sha256
import unittest
from pathlib import Path
import tempfile

import transport_source


class PinnedTransportTests(unittest.TestCase):
    def test_edges_are_bound_to_one_exact_consumer_identity_and_feature_set(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work).resolve() / "repo"
            name = "russh"
            dependency = {
                "name": name, "req": "=0.65.4", "kind": None, "target": None, "source": None,
                "rename": None, "optional": True, "uses_default_features": False, "features": ["ring"],
                "path": str(transport_source.sibling(source, name)),
            }
            match = transport_source.dependency_edge_matches
            self.assertTrue(match(dependency, source, "exacopy-ssh"))
            self.assertFalse(match(dependency, source, "exacopy-wireguard"))
            for edit in (
                {"req": "0.65"}, {"target": "cfg(unix)"}, {"kind": "build"}, {"optional": False},
                {"uses_default_features": True}, {"features": []}, {"rename": "other"},
                {"source": "registry+https://github.com/rust-lang/crates.io-index"},
                {"path": str(source.parent / "unreviewed" / name)},
            ):
                with self.subTest(edit=edit):
                    self.assertFalse(match(dependency | edit, source, "exacopy-ssh"))

    def test_utility_patch_requires_exact_transitive_source(self):
        source = {"version": "=0.52.0", "path": "../local-deps/russh-util"}
        layout = {"workspace": {"dependencies": {}}, "patch": {"crates-io": {"russh-util": source}}}
        verify = transport_source.verify_utility_patch
        verify(layout, "0.52.0")
        for entry in (
            {},
            source | {"path": "../unreviewed/russh-util"},
            source | {"version": "0.52"},
            source | {"git": "https://example.invalid/repository"},
        ):
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "exact transitive"):
                verify(layout | {"patch": {"crates-io": {"russh-util": entry}}}, "0.52.0")
        with self.assertRaisesRegex(ValueError, "exact transitive"):
            verify(layout | {"workspace": {"dependencies": {"russh-util": source}}}, "0.52.0")

    def test_only_manifest_repairs_require_separate_manifest_hashes(self):
        project = Path(__file__).resolve().parents[1]
        pinned = (project / transport_source.PIN).read_text(encoding="utf-8")
        pins = transport_source.read_pins(project)
        with tempfile.TemporaryDirectory() as work:
            source = Path(work)
            path = source / transport_source.PIN
            path.parent.mkdir(parents=True)
            for name in ("boringtun", "russh-util"):
                digest = pins[name]["repaired_manifest_sha256"]
                field = f'repaired_manifest_sha256 = "{digest}"'
                without_field = pinned.replace(field + "\n", "", 1)
                self.assertNotEqual(without_field, pinned)
                with self.subTest(name=name):
                    path.write_text(without_field, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, f"invalid {name} source pin"):
                        transport_source.read_pins(source)
            extra_field = f'repaired_manifest_sha256 = "{"a" * 64}"'
            path.write_text(
                pinned.replace("[russh]\n", f"[russh]\n{extra_field}\n", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid russh source pin"):
                transport_source.read_pins(source)

    def test_manifest_repairs_distinguish_publisher_and_installed_bytes(self):
        with tempfile.TemporaryDirectory() as work:
            manifest = Path(work) / "Cargo.toml"
            for name in ("boringtun", "russh-util"):
                version, _, _, license_name, repository = transport_source.POLICY[name]
                published = (
                    f'[package]\nname = "{name}"\nversion = "{version}"\n'
                    f'license = "{license_name}"\nrepository = "{repository}"\n'
                ).encode()
                repaired = published + b"\n# Manifest repair\n"
                upstream = "1" * 40
                vcs = {"git": {"sha1": upstream}}
                pin = {
                    "version": version, "license": license_name, "upstream_repository": repository,
                    "upstream_commit": upstream, "normalized_manifest_sha256": sha256(published).hexdigest(),
                    "repaired_manifest_sha256": sha256(repaired).hexdigest(),
                }
                with self.subTest(name=name):
                    transport_source.verify_package_metadata(published, vcs, name, pin)
                    with self.assertRaisesRegex(ValueError, "normalized manifest"):
                        transport_source.verify_package_metadata(repaired, vcs, name, pin)
                    manifest.write_bytes(repaired)
                    transport_source.verify_repaired_manifest(manifest.parent, name, pin)
                    manifest.write_bytes(published)
                    with self.assertRaisesRegex(ValueError, "repaired manifest"):
                        transport_source.verify_repaired_manifest(manifest.parent, name, pin)

    def test_modified_path_never_matches_a_registry_component(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work).resolve() / "repo"
            name = "boringtun"
            package = {
                "name": name, "version": "0.7.1", "source": None, "license": "BSD-3-Clause",
                "repository": "https://github.com/cloudflare/boringtun",
                "manifest_path": str(transport_source.sibling(source, name) / "Cargo.toml"),
            }
            self.assertTrue(transport_source.package_matches(package, source))
            package["source"] = "registry+https://github.com/rust-lang/crates.io-index"
            self.assertFalse(transport_source.package_matches(package, source))

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

    def test_utility_repair_binds_new_manifest_without_relabeling_registry_preimage(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            published = b"published manifest"
            repaired = b"repaired manifest"
            pin = {
                "normalized_manifest_sha256": sha256(published).hexdigest(),
                "repaired_manifest_sha256": sha256(repaired).hexdigest(),
            }
            manifest = root / "Cargo.toml"
            manifest.write_bytes(repaired)
            transport_source.verify_repaired_manifest(root, "russh-util", pin)
            manifest.write_bytes(published)
            with self.assertRaisesRegex(ValueError, "repaired manifest"):
                transport_source.verify_repaired_manifest(root, "russh-util", pin)

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

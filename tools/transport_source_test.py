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

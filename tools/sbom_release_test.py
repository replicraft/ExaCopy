"""Positive and negative controls for deriving a BOM from Cargo build messages."""

import json
from pathlib import Path
import unittest

from sbom_release import build_inputs, component


def artifact(package, target_kind, features, binary=None):
    return json.dumps({
        "reason": "compiler-artifact",
        "package_id": package,
        "target": {"name": "exacopy" if binary else package, "kind": [target_kind]},
        "features": features,
        "executable": binary,
    })


class SbomReleaseTests(unittest.TestCase):
    def test_build_input_inventory_retains_build_and_library_units(self):
        artifacts = [
            artifact("integrity", "custom-build", ["a"]),
            artifact("integrity", "lib", ["b"]),
            artifact("integrity", "lib", ["a"]),
            artifact("cli", "bin", [], "/target/release/exacopy"),
            '{"reason":"build-script-executed"}',
        ]
        units, executable = build_inputs(artifacts)
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


if __name__ == "__main__":
    unittest.main()

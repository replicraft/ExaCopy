"""Negative controls for the feature and dependency policy."""

from copy import deepcopy
import json
import unittest

from feature_matrix import MATRIX, check_cli_graph, check_manifests, profile_flags

POLICY = json.loads(MATRIX.read_text(encoding="utf-8"))
LINUX = "x86_64-unknown-linux-gnu"
MACOS = "aarch64-apple-darwin"


class FeatureMatrixTests(unittest.TestCase):
    def test_unreviewed_feature_is_rejected(self):
        packages = [
            {"name": name, "features": {}, "dependencies": []}
            for group in ("production_packages", "engineering_packages") for name in POLICY[group]
        ]
        for package in packages:
            package["features"] = {
                name: config["enables"]
                for name, config in POLICY["features"].get(package["name"], {}).items()
            }
        model = next(package for package in packages if package["name"] == "exacopy-model")
        model["features"]["unchecked-publication"] = []
        with self.assertRaisesRegex(ValueError, "unchecked-publication"):
            check_manifests(POLICY, packages)

    def test_implicit_production_dependency_defaults_are_rejected(self):
        policy = {
            "production_packages": ["model"],
            "engineering_packages": [],
            "features": {},
            "production_dependencies": {"uuid": POLICY["production_dependencies"]["uuid"]},
        }
        dependency = {
            "name": "uuid", "kind": None, "source": "registry", "target": None,
            "uses_default_features": False, "features": [], "optional": False,
        }
        packages = [{"name": "model", "features": {}, "dependencies": [dependency]}]
        check_manifests(policy, packages)
        dependency["uses_default_features"] = True
        with self.assertRaisesRegex(ValueError, "uuid feature selection differs"):
            check_manifests(policy, packages)

    def test_cli_rejects_missing_integrity_and_unrelated_dependencies(self):
        target = POLICY["targets"][LINUX]
        groups = POLICY["cli_graph_groups"]
        graph = {name: set() for group in target["cli_graph_groups"] for name in groups[group]}
        graph["rustix"] = set(target["rustix_features"])
        graph["ed25519-dalek"] = {"zeroize"}
        graph["clap"] = {"error-context", "help", "std", "usage"}
        graph["base64"] = {"alloc"}
        graph["chrono"] = {"alloc"}
        check_cli_graph(POLICY, LINUX, graph)
        defaulted = deepcopy(graph)
        defaulted["clap"].add("default")
        with self.assertRaisesRegex(ValueError, "CLI dependency clap"):
            check_cli_graph(POLICY, LINUX, defaulted)
        defaulted = deepcopy(graph)
        defaulted["base64"].update({"std", "simd-unsafe"})
        with self.assertRaisesRegex(ValueError, "CLI dependency base64"):
            check_cli_graph(POLICY, LINUX, defaulted)
        clock_enabled = deepcopy(graph)
        clock_enabled["chrono"].update({"clock", "std"})
        with self.assertRaisesRegex(ValueError, "CLI dependency chrono"):
            check_cli_graph(POLICY, LINUX, clock_enabled)
        corrupted = deepcopy(graph)
        del corrupted["blake3"]
        corrupted["unreviewed-network-library"] = set()
        with self.assertRaisesRegex(ValueError, "unexpected.*unreviewed-network-library.*missing.*blake3"):
            check_cli_graph(POLICY, LINUX, corrupted)

    def test_experimental_apfs_feature_is_target_scoped_and_default_off(self):
        profiles = POLICY["profiles"]
        for package in ("exacopy-transfer", "exacopy-engine"):
            feature = f"{package}/experimental-apfs-copy"
            for profile in ("default", "minimal", "all-stable"):
                self.assertNotIn(feature, ",".join(profile_flags(POLICY, profiles[profile], MACOS)))
            opt_in = ",".join(profile_flags(POLICY, profiles["experimental-apfs-copy"], MACOS))
            self.assertIn(feature, opt_in.split(","))
            self.assertNotIn(feature, ",".join(profile_flags(POLICY, profiles["development-all"], LINUX)))


if __name__ == "__main__":
    unittest.main()

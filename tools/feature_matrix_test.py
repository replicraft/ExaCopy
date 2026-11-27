"""Negative controls for the feature and dependency policy."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from feature_matrix import (
    MATRIX, check_cli_graph, check_isolated_features, check_manifests, profile_flags, resolved_graph,
)

POLICY = json.loads(MATRIX.read_text(encoding="utf-8"))
LINUX = "x86_64-unknown-linux-gnu"
MACOS = "aarch64-apple-darwin"
WINDOWS = "x86_64-pc-windows-msvc"


class FeatureMatrixTests(unittest.TestCase):
    def test_ci_feature_matrix_invocations_disable_bytecode_writes(self):
        invocations = [
            (workflow, line)
            for workflow in Path(".github/workflows").glob("*.yml")
            for line in workflow.read_text(encoding="utf-8").splitlines()
            if " tools/feature_matrix.py " in line
        ]
        self.assertTrue(invocations)
        for workflow, invocation in invocations:
            with self.subTest(workflow=workflow):
                self.assertIn(" -B tools/feature_matrix.py ", invocation)

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
        graph["rustix@1.1.6"] = set(target["rustix_features"])
        graph["ed25519-dalek@3.0.0"] = {"zeroize"}
        graph["clap@4.6.10"] = {"error-context", "help", "std", "usage"}
        graph["base64@0.23.1"] = {"alloc"}
        graph["nix@0.31.4"] = {"feature"}
        check_cli_graph(POLICY, LINUX, graph)
        legacy_compatibility = deepcopy(graph)
        legacy_compatibility["ed25519-dalek@3.0.0"].add("legacy_compatibility")
        with self.assertRaisesRegex(ValueError, "CLI dependency ed25519-dalek"):
            check_cli_graph(POLICY, LINUX, legacy_compatibility)
        unrelated_nix = deepcopy(graph)
        unrelated_nix["nix@0.31.4"].add("mman")
        with self.assertRaisesRegex(ValueError, "CLI dependency nix"):
            check_cli_graph(POLICY, LINUX, unrelated_nix)
        defaulted = deepcopy(graph)
        defaulted["clap@4.6.10"].add("default")
        with self.assertRaisesRegex(ValueError, "CLI dependency clap"):
            check_cli_graph(POLICY, LINUX, defaulted)
        defaulted = deepcopy(graph)
        defaulted["base64@0.23.1"].update({"std", "simd-unsafe"})
        with self.assertRaisesRegex(ValueError, "CLI dependency base64"):
            check_cli_graph(POLICY, LINUX, defaulted)
        clock_enabled = deepcopy(graph)
        clock_enabled["jiff@1.0.3"].update({"std", "tz-system"})
        with self.assertRaisesRegex(ValueError, "CLI dependency jiff"):
            check_cli_graph(POLICY, LINUX, clock_enabled)
        corrupted = deepcopy(graph)
        del corrupted["blake3@1.8.7"]
        corrupted["unreviewed-network-library@1.0.0"] = set()
        with self.assertRaisesRegex(ValueError, "unexpected.*unreviewed-network-library.*missing.*blake3"):
            check_cli_graph(POLICY, LINUX, corrupted)

        duplicate_version = graph | {"base64@0.22.1": graph["base64@0.23.1"].copy()}
        with self.assertRaisesRegex(ValueError, r"unexpected.*base64@0\.22\.1"):
            check_cli_graph(POLICY, LINUX, duplicate_version)

    def test_resolved_graph_does_not_merge_same_name_versions(self):
        def cargo(*args, **kwargs):
            return "base64 v0.22.1\talloc\nbase64 v0.23.1\talloc\n"

        self.assertEqual(
            resolved_graph(cargo, ["exacopy-cli"], LINUX, []),
            {"base64@0.22.1": {"alloc"}, "base64@0.23.1": {"alloc"}},
        )

    def test_experimental_apfs_feature_is_target_scoped_and_default_off(self):
        profiles = POLICY["profiles"]
        for package in ("exacopy-transfer", "exacopy-cli"):
            feature = f"{package}/experimental-apfs-copy"
            for profile in ("default", "minimal", "all-stable"):
                self.assertNotIn(feature, ",".join(profile_flags(POLICY, profiles[profile], MACOS)))
            opt_in = ",".join(profile_flags(POLICY, profiles["experimental-apfs-copy"], MACOS))
            self.assertIn(feature, opt_in.split(","))
            self.assertNotIn(feature, ",".join(profile_flags(POLICY, profiles["development-all"], LINUX)))

    def test_protocol_profile_isolated_and_default_off_on_every_target(self):
        profiles = POLICY["profiles"]
        feature = "exacopy-wireguard/experimental-protocol"
        standalone = "experimental-wireguard-protocol"
        udp = "exacopy-wireguard/experimental-udp"
        udp_profile = "experimental-wireguard-udp"
        tcp = "exacopy-wireguard/experimental-tcp"
        tcp_profile = "experimental-wireguard-tcp"
        combined = "experimental-wireguard-tcp-udp"
        for target in POLICY["targets"]:
            with self.subTest(target=target):
                for profile, config in profiles.items():
                    flags = profile_flags(POLICY, config, target)
                    selectors = ",".join(flags).split(",")
                    if profile == "experimental-ssh-wireguard" and target == LINUX:
                        self.assertEqual(set(selectors[2:]), {
                            "exacopy-cli/experimental-ssh-capture",
                            "exacopy-cli/experimental-ssh-wireguard",
                            "exacopy-sftp/experimental-sftp",
                            "exacopy-ssh/experimental-ssh",
                            feature, udp, tcp,
                        })
                        continue
                    if profile not in {standalone, udp_profile, tcp_profile, combined, "development-all"}:
                        self.assertNotIn(feature, selectors)
                    if profile not in {udp_profile, combined, "development-all"}:
                        self.assertNotIn(udp, selectors)
                    if profile not in {tcp_profile, combined, "development-all"}:
                        self.assertNotIn(tcp, selectors)
                self.assertEqual(
                    profile_flags(POLICY, profiles[standalone], target),
                    ["--no-default-features", "--features", feature],
                )
                self.assertEqual(
                    profile_flags(POLICY, profiles[udp_profile], target),
                    ["--no-default-features", "--features", f"{feature},{udp}"],
                )
                self.assertEqual(
                    profile_flags(POLICY, profiles[tcp_profile], target),
                    ["--no-default-features", "--features", f"{feature},{tcp}"],
                )
                self.assertEqual(
                    profile_flags(POLICY, profiles[combined], target),
                    ["--no-default-features", "--features", f"{feature},{tcp},{udp}"],
                )
                development = ",".join(
                    profile_flags(POLICY, profiles["development-all"], target)
                ).split(",")
                self.assertIn(feature, development)
                self.assertIn(udp, development)
                self.assertIn(tcp, development)

    def test_sftp_profiles_are_explicit_and_app_capture_is_independent_of_apfs(self):
        profiles = POLICY["profiles"]
        adapter = "exacopy-sftp/experimental-sftp"
        ssh = "exacopy-ssh/experimental-ssh"
        app = "exacopy-cli/experimental-ssh-capture"
        for target in POLICY["targets"]:
            with self.subTest(target=target):
                for name in ("default", "minimal", "all-stable"):
                    flags = ",".join(profile_flags(POLICY, profiles[name], target)).split(",")
                    for selector in (adapter, ssh, app):
                        self.assertNotIn(selector, flags)
                self.assertEqual(
                    profile_flags(POLICY, profiles["experimental-sftp"], target),
                    ["--no-default-features", "--features", f"{adapter},{ssh}"],
                )
                capture_flags = profile_flags(POLICY, profiles["experimental-ssh-capture"], target)
                expected = ["--no-default-features"]
                if target != WINDOWS:
                    expected += ["--features", f"{app},{adapter},{ssh}"]
                self.assertEqual(capture_flags, expected)

    def test_sftp_capture_policy_refuses_implicit_apfs_or_missing_transport(self):
        name = "experimental-ssh-capture"
        profile = POLICY["profiles"][name]
        selected = {
            "exacopy-cli@0.1.0": {"experimental-ssh-capture"},
            "exacopy-sftp@0.1.0": {"experimental-sftp"},
            "exacopy-ssh@0.1.0": {"experimental-ssh"},
            "exacopy-transfer@0.1.0": set(),
        }
        check_isolated_features(POLICY, MACOS, name, profile, selected)
        implicit_apfs = selected | {"exacopy-transfer@0.1.0": {"experimental-apfs-copy"}}
        with self.assertRaisesRegex(ValueError, "unexpected.*exacopy-transfer/experimental-apfs-copy"):
            check_isolated_features(POLICY, MACOS, name, profile, implicit_apfs)
        missing_transport = selected | {"exacopy-ssh@0.1.0": set()}
        with self.assertRaisesRegex(ValueError, "missing.*exacopy-ssh/experimental-ssh"):
            check_isolated_features(POLICY, MACOS, name, profile, missing_transport)

    def test_optional_dependency_is_scoped_to_its_named_consumer(self):
        rule = {"default_features": False, "features": [], "optional_consumers": ["ssh"]}
        policy = {
            "production_packages": ["cli", "ssh"], "engineering_packages": [], "features": {},
            "production_dependencies": {"zeroize": rule},
        }
        dependency = {
            "name": "zeroize", "kind": None, "source": "registry", "target": None,
            "uses_default_features": False, "features": [], "optional": False,
        }
        packages = [
            {"name": "cli", "features": {}, "dependencies": [dependency]},
            {"name": "ssh", "features": {}, "dependencies": [dependency | {"optional": True}]},
        ]
        check_manifests(policy, packages)
        packages[1]["dependencies"][0]["optional"] = False
        with self.assertRaisesRegex(ValueError, "ssh: zeroize feature selection differs"):
            check_manifests(policy, packages)

    def test_isolated_profiles_ignore_new_same_owner_features(self):
        policy = deepcopy(POLICY)
        for name, target, selectors in (
            ("experimental-apfs-copy", MACOS, [
                "exacopy-cli/experimental-apfs-copy", "exacopy-transfer/experimental-apfs-copy",
            ]),
            ("experimental-windows-copy", WINDOWS, [
                "exacopy-platform/experimental-windows-copy", "exacopy-platform/windows-read-fixture",
            ]),
            ("experimental-wireguard-protocol", LINUX, ["exacopy-wireguard/experimental-protocol"]),
            ("experimental-wireguard-udp", LINUX, [
                "exacopy-wireguard/experimental-protocol", "exacopy-wireguard/experimental-udp",
            ]),
            ("experimental-ssh", LINUX, ["exacopy-ssh/experimental-ssh"]),
        ):
            with self.subTest(profile=name):
                owner = selectors[0].partition("/")[0]
                policy["features"][owner]["future-experiment"] = {"status": "experimental"}
                self.assertEqual(
                    profile_flags(policy, policy["profiles"][name], target),
                    ["--no-default-features", "--features", ",".join(selectors)],
                )
                self.assertIn(
                    f"{owner}/future-experiment",
                    ",".join(profile_flags(policy, policy["profiles"]["development-all"], target)),
                )

    def test_exact_selector_rejects_unknown_unavailable_and_mixed_selectors(self):
        profile = POLICY["profiles"]["experimental-wireguard-protocol"]
        for selectors, error in (
            (["exacopy-wireguard/experimental-typo"], "unknown.*experimental-typo"),
            (["exacopy-platform/windows-read-fixture"], "unavailable on a profile target"),
            (["exacopy-model/proof-extraction"], "non-experimental"),
            (profile["exact_features"] * 2, "duplicate"),
        ):
            with self.subTest(selectors=selectors):
                with self.assertRaisesRegex(ValueError, error):
                    profile_flags(POLICY, profile | {"exact_features": selectors}, LINUX)
        with self.assertRaisesRegex(ValueError, "isolated profile"):
            profile_flags(POLICY, profile | {"feature_statuses": ["experimental"]}, LINUX)
        with self.assertRaisesRegex(ValueError, "use exact_features"):
            profile_flags(POLICY, profile | {"feature_packages": ["exacopy-wireguard"]}, LINUX)

    def test_resolved_network_feature_leaks_are_rejected(self):
        policy = deepcopy(POLICY)
        policy["production_packages"].append("exacopy-ssh")
        policy["features"]["exacopy-ssh"] = {"experimental-ssh": {"status": "experimental"}}
        for owner, feature in (
            ("exacopy-wireguard", "experimental-protocol"), ("exacopy-ssh", "experimental-ssh"),
        ):
            profile = POLICY["profiles"]["experimental-wireguard-protocol"] | {
                "exact_features": [f"{owner}/{feature}"],
            }
            normal = {f"{owner}@0.1.0": {feature}, "exacopy-platform@0.1.0": set()}
            check_isolated_features(policy, WINDOWS, "network", profile, normal)
            for package, accidental in (
                (owner, "future-experiment"),
                ("exacopy-cli", "experimental-apfs-copy"),
                ("exacopy-platform", "experimental-windows-copy"),
                ("exacopy-platform", "windows-read-fixture"),
                ("exacopy-model", "proof-extraction"),
                ("exacopy-ssh", "experimental-ssh") if owner == "exacopy-wireguard"
                else ("exacopy-wireguard", "experimental-protocol"),
            ):
                with self.subTest(owner=owner, accidental=accidental):
                    corrupted = deepcopy(normal)
                    corrupted.setdefault(f"{package}@0.1.0", set()).add(accidental)
                    with self.assertRaisesRegex(ValueError, f"unexpected.*{package}/{accidental}"):
                        check_isolated_features(policy, WINDOWS, "network", profile, corrupted)


if __name__ == "__main__":
    unittest.main()

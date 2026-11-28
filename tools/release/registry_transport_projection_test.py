#!/usr/bin/env python3
"""Check the optional registry projection and fail-closed transport provenance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import registry_projection as base
import registry_transport_projection as transport


class TransportProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default = base.toml(base.POLICY.read_bytes())
        cls.selected = base.toml(transport.POLICY.read_bytes())
        cls.commit = base.git(base.ROOT, "rev-parse", "HEAD").decode().strip()
        cls.files = transport.render_transport(base.ROOT, cls.commit, cls.default, cls.selected)
        cls.record = json.loads(cls.files["projection.json"])

    def test_selected_features_preserve_defaults_and_repaired_aliases(self):
        expected = {
            "experimental-linux-managed-sync", "experimental-ssh-capture",
            "experimental-ssh-wireguard", "experimental-windows-diff",
        }
        cli = base.toml(self.files["exacopy/Cargo.toml"])
        self.assertEqual(set(cli["features"]), expected)
        self.assertEqual(cli["profile"]["release"], {"overflow-checks": True})
        self.assertIn('dep:exacopy-wireguard', cli["features"]["experimental-ssh-wireguard"])
        self.assertIn('exacopy-wireguard?/experimental-tcp', cli["features"]["experimental-ssh-wireguard"])
        ssh = base.toml(self.files["exacopy-ssh/Cargo.toml"])
        wg = base.toml(self.files["exacopy-wireguard/Cargo.toml"])
        russh = base.toml(self.files["exacopy-russh/Cargo.toml"])
        self.assertEqual(ssh["dependencies"]["russh"]["package"], "exacopy-russh")
        self.assertEqual(wg["dependencies"]["boringtun"]["package"], "exacopy-boringtun")
        self.assertEqual(russh["dependencies"]["russh-util"]["package"], "exacopy-russh-util")
        self.assertEqual(russh["dependencies"]["russh-util"]["version"], "=0.1.0")
        self.assertEqual(russh["features"], {"ring": ["dep:ring"]})
        self.assertEqual(len(self.record["packages"]), 14)
        self.assertFalse(self.record["registry_publication_verified"])
        self.assertTrue(self.record["external_companion"]["canonical_registry_archive_required"])

    def test_boringtun_projection_excludes_optional_device_router_dependencies(self):
        name = "exacopy-boringtun"
        manifest = base.toml(self.files[f"{name}/Cargo.toml"])
        receipt = next(entry for entry in self.record["transport_forks"] if entry["name"] == name)
        device_dependencies = {"ip_network", "ip_network_table", "socket2", "thiserror"}
        self.assertEqual(manifest.get("features", {}), {})
        for scope in (manifest, *manifest.get("target", {}).values()):
            for kind in ("dependencies", "build-dependencies"):
                self.assertTrue(device_dependencies.isdisjoint(scope.get(kind, {})))
        self.assertTrue(device_dependencies.isdisjoint(receipt["dependencies"]))

    def test_platform_projection_preserves_exact_optional_target_edges(self):
        cli = base.toml(self.files["exacopy/Cargo.toml"])
        platform = base.toml(self.files["exacopy-platform/Cargo.toml"])
        native = {
            name: base.toml(base.git(base.ROOT, "show", f"{self.commit}:{path}"))
            for name, path in (
                ("cli", "apps/exacopy-cli/Cargo.toml"),
                ("platform", "crates/platform/exacopy-platform/Cargo.toml"),
            )
        }
        for scope, manifest in (("cli", cli), ("platform", platform)):
            with self.subTest(scope=scope):
                expected = native[scope]["features"]
                self.assertEqual(manifest["features"], {key: expected[key] for key in manifest["features"]})
        self.assertEqual(set(platform["features"]), {"experimental-linux-managed-sync", "experimental-windows-read"})
        windows = 'cfg(target_os = "windows")'
        held_linux = 'cfg(all(target_os = "linux", target_pointer_width = "64", any(target_arch = "x86_64", target_arch = "aarch64")))'
        self.assertEqual(set(cli["target"][windows]["dependencies"]), {"exacopy-diff", "exacopy-endpoint", "exacopy-platform"})
        self.assertEqual(set(platform["target"][windows]["dependencies"]), {"exacopy-endpoint", "windows-sys"})
        self.assertEqual(set(platform["target"][held_linux]["dependencies"]), {"libc"})
        for dependencies in (
            cli["target"][windows]["dependencies"],
            platform["target"][windows]["dependencies"],
            platform["target"][held_linux]["dependencies"],
        ):
            self.assertTrue(all(dependency["optional"] is True for dependency in dependencies.values()))
        self.assertFalse(platform["target"][windows]["dependencies"]["windows-sys"]["default-features"])

    def test_refuses_default_activation_and_unrecognized_feature_packages(self):
        changed = copy.deepcopy(self.selected)
        changed["existing_features"]["exacopy"].append("default")
        with self.assertRaisesRegex(ValueError, "default-off"):
            transport.transport_policy(self.default, changed)
        changed = copy.deepcopy(self.selected)
        changed["existing_features"]["apfs-mounted"] = ["experimental"]
        with self.assertRaisesRegex(ValueError, "requires exactly the CLI and platform feature owners"):
            transport.transport_policy(self.default, changed)

    def test_refuses_missing_runtime_feature_owners_or_flags(self):
        expected = "requires exactly the CLI and platform feature owners"
        changed = copy.deepcopy(self.selected)
        del changed["existing_features"]
        with self.assertRaisesRegex(ValueError, expected):
            transport.transport_policy(self.default, changed)
        for owner in ("exacopy", "exacopy-platform"):
            with self.subTest(owner=owner):
                changed = copy.deepcopy(self.selected)
                del changed["existing_features"][owner]
                with self.assertRaisesRegex(ValueError, expected):
                    transport.transport_policy(self.default, changed)
                features = self.selected["existing_features"][owner]
                for invalid in ([], {"unexpected": True}, features[:-1], features[:-1] + [features[0]]):
                    changed = copy.deepcopy(self.selected)
                    changed["existing_features"][owner] = invalid
                    with self.assertRaisesRegex(ValueError, f"exact default-off runtime features for {owner}"):
                        transport.transport_policy(self.default, changed)

    def test_source_and_notice_receipts(self):
        for receipt in self.record["transport_forks"]:
            name = receipt["name"]
            self.assertEqual(base.digest(self.files[f"{name}/EXACOPY-MODIFICATIONS.patch"]), receipt["attribution_patch_sha256"])
            for file, sha256 in receipt["files_sha256"].items():
                self.assertEqual(base.digest(self.files[f"{name}/{file}"]), sha256)
            self.assertTrue(any(file.startswith("LICENSE") for file in receipt["files_sha256"]))

    def test_rejects_changed_transport_policy_and_missing_forks(self):
        changed = copy.deepcopy(self.selected)
        changed["transport_pins_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unexpected SHA-256"):
            transport.render_transport(base.ROOT, self.commit, self.default, changed)
        changed = copy.deepcopy(self.selected)
        changed["forks"].pop()
        with self.assertRaisesRegex(ValueError, "requires all three"):
            transport.render_transport(base.ROOT, self.commit, self.default, changed)

    def test_rejects_invalid_or_colliding_downstream_names(self):
        for name in ("../escaped", "apfs-mounted", "exacopy", "exacopy-russh"):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.selected)
                changed["forks"][0]["name"] = name
                with self.assertRaisesRegex(ValueError, "unexpected downstream transport package identity"):
                    transport.render_transport(base.ROOT, self.commit, self.default, changed)
        changed = copy.deepcopy(self.selected)
        changed["forks"].append(changed["forks"][0].copy())
        with self.assertRaisesRegex(ValueError, "requires all three"):
            transport.render_transport(base.ROOT, self.commit, self.default, changed)

    def test_rejects_unsafe_output_paths_before_create(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            destination = stage / "destination"
            for bad in ("../escaped", "/absolute/path", "C:/root", "sub\\file", "sub/../escaped"):
                with self.subTest(path=bad):
                    with self.assertRaisesRegex(ValueError, "outside its staging directory"):
                        base.write_projection(destination, {"valid/file": b"data", bad: b"data"})
                    self.assertEqual(list(stage.iterdir()), [])

    def test_opt_in_is_separate_and_does_not_change_default(self):
        self.assertNotIn("features", self.default["packages"][-1])
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            base.project(base.ROOT, self.commit, stage / "default", self.default)
            manifest = base.toml((stage / "default/exacopy/Cargo.toml").read_bytes())
            self.assertNotIn("features", manifest)
            self.assertFalse((stage / "default/exacopy-russh").exists())
            self.assertFalse((stage / "default/exacopy-ssh").exists())


if __name__ == "__main__":
    unittest.main()

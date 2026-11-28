#!/usr/bin/env python3
"""Check the default registry package projection against immutable Git inputs."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import registry_projection as projection
import registry_transport_projection as transport


class RegistryProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = projection.toml(projection.POLICY.read_bytes())
        cls.commit = projection.git(projection.ROOT, "rev-parse", "HEAD").decode().strip()
        paths = ["Cargo.toml", "Cargo.lock", "LICENSE", projection.APFS_PIN]
        for package in cls.policy["packages"]:
            paths.extend((f"{package['path']}/Cargo.toml", f"{package['path']}/src"))
        cls.source = projection.source_files(projection.ROOT, cls.commit, paths)
        cls.files = projection.render(cls.source, cls.commit, cls.policy)

    def test_copies_all_canonical_source_and_retains_an_external_companion(self):
        record = json.loads(self.files["projection.json"])
        self.assertEqual(record["source_commit"], self.commit)
        self.assertEqual(record["external_companion"]["name"], "apfs-mounted")
        self.assertEqual(record["external_companion"]["version"], "0.1.0")
        self.assertEqual(record["workspace_lock_sha256"], hashlib.sha256(self.source["Cargo.lock"]).hexdigest())
        self.assertEqual(
            {package["name"] for package in record["packages"]},
            {"exacopy", "exacopy-content", "exacopy-core", "exacopy-diff", "exacopy-endpoint", "exacopy-journal",
             "exacopy-manifest", "exacopy-model", "exacopy-plan", "exacopy-platform", "exacopy-transfer"},
        )
        for package in record["packages"]:
            name, root = package["name"], package["source_path"]
            for file, expected in package["files_sha256"].items():
                data = self.files[f"{name}/{file}"]
                self.assertEqual(projection.digest(data), expected)
                if file.startswith("src/"):
                    self.assertEqual(data, self.source[f"{root}/{file}"])
            expected_sources = {file.removeprefix(f"{root}/") for file in self.source if file.startswith(f"{root}/src/")}
            self.assertEqual(expected_sources, {file for file in package["files_sha256"] if file.startswith("src/")})

    def test_cli_retains_binary_library_target_and_overflow_checks(self):
        manifest = projection.toml(self.files["exacopy/Cargo.toml"])
        self.assertEqual(manifest["package"]["name"], "exacopy")
        self.assertEqual(manifest["package"]["rust-version"], "1.100.0")
        self.assertEqual(manifest["package"]["resolver"], "3")
        self.assertEqual(manifest["package"]["edition"], "2024")
        self.assertEqual(manifest["lib"]["name"], "exacopy_cli")
        self.assertEqual(manifest["lib"]["path"], "src/lib.rs")
        self.assertEqual(manifest["bin"][0]["name"], "exacopy")
        self.assertEqual(manifest["bin"][0]["path"], "src/main.rs")
        self.assertEqual(manifest["profile"]["release"], {"overflow-checks": True})
        self.assertNotIn("features", manifest)
        self.assertNotIn("patch", manifest)
        self.assertNotIn('cfg(target_os = "windows")', manifest["target"])
        self.assertIn("experimental-ssh-capture", manifest["lints"]["rust"]["unexpected_cfgs"]["check-cfg"][1])
        linux = manifest["target"]['cfg(target_os = "linux")']["dependencies"]
        self.assertNotIn("exacopy-wireguard", linux)
        self.assertEqual(linux["rustix"]["features"], ["fs", "process"])
        macos = projection.toml(self.files["exacopy-platform/Cargo.toml"])["target"]
        macos = macos['cfg(target_os = "macos")']["dependencies"]
        self.assertEqual(macos["apfs-mounted"], {"version": "=0.1.0", "default-features": False})
        self.assertEqual(macos["rustix"]["features"], ["fs", "process", "try_close"])

    def test_transport_cli_omits_windows_sdk_edges_only(self):
        selected = projection.toml(transport.POLICY.read_bytes())
        policy = transport.transport_policy(self.policy, selected)
        workspace = projection.toml(self.source["Cargo.toml"])
        packages = {package["source_name"]: package for package in policy["packages"]}
        forks = {fork["source_name"]: fork for fork in selected["forks"]}
        cli = packages["exacopy-cli"]
        source = projection.checked_manifest(
            self.source["apps/exacopy-cli/Cargo.toml"], cli["manifest_sha256"], "apps/exacopy-cli/Cargo.toml",
        )
        args = (workspace["workspace"], workspace["profile"]["release"], cli, packages, forks)
        staged, _ = projection.standalone_manifest(source, *args)
        manifest = projection.toml(staged)
        self.assertNotIn("experimental-windows-sftp-capture", manifest["features"])
        windows = 'cfg(target_os = "windows")'
        self.assertEqual(set(manifest["target"][windows]["dependencies"]), {
            "exacopy-diff", "exacopy-endpoint", "exacopy-platform",
        })
        posix = 'cfg(any(target_os = "linux", target_os = "macos"))'
        self.assertTrue({"exacopy-sftp", "exacopy-ssh"} <= manifest["target"][posix]["dependencies"].keys())
        linux = 'cfg(target_os = "linux")'
        self.assertTrue({"exacopy-transfer", "tokio"} <= manifest["target"][linux]["dependencies"].keys())

        dependencies = source["target"][windows]["dependencies"]
        for replacement in ({"workspace": True}, None):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    del dependencies["tokio"]
                else:
                    dependencies["tokio"] = replacement
                with self.assertRaisesRegex(ValueError, "requires an optional dependency to omit .*?/tokio"):
                    projection.standalone_manifest(source, *args)

    def test_refuses_changed_features_and_dependency_sources(self):
        updated = self.source.copy()
        path = "apps/exacopy-cli/Cargo.toml"
        updated[path] = updated[path].replace(b"[features]", b'[features]\ndefault = ["experimental-ssh-capture"]')
        with self.assertRaisesRegex(ValueError, "policy needs review for changed"):
            projection.render(updated, self.commit, self.policy)
        updated = self.source.copy()
        updated["Cargo.toml"] = updated["Cargo.toml"].replace(b'path = "../pomologie/apfs/', b'path = "../alternate/apfs/')
        with self.assertRaisesRegex(ValueError, "policy needs review for changed"):
            projection.render(updated, self.commit, self.policy)

    def test_omits_experimental_mount_feature_and_its_optional_native_dependency(self):
        manifest = projection.toml(self.files["exacopy-platform/Cargo.toml"])
        self.assertNotIn("features", manifest)
        self.assertNotIn("test", manifest)
        linux = manifest["target"]['cfg(target_os = "linux")']["dependencies"]
        self.assertNotIn("libc", linux)
        self.assertFalse(any("target_pointer_width" in target for target in manifest["target"]))
        self.assertIn("experimental-linux-managed-sync", json.dumps(manifest["lints"]))

    def test_refuses_missing_cli_library_and_inverted_package_order(self):
        incomplete = self.source.copy()
        del incomplete["apps/exacopy-cli/src/lib.rs"]
        with self.assertRaisesRegex(ValueError, "source entries missing in .*src/lib.rs"):
            projection.render(incomplete, self.commit, self.policy)
        policy = copy.deepcopy(self.policy)
        policy["packages"].reverse()
        with self.assertRaisesRegex(ValueError, "dependency order"):
            projection.render(self.source, self.commit, policy)

    def test_cargo_parses_standalone_artifacts_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory(prefix="exacopy-registry-projection-test-") as scratch:
            output = Path(scratch) / "staged"
            projection.project(projection.ROOT, self.commit, output, self.policy)
            files = {file.relative_to(output).as_posix(): file.read_bytes() for file in output.rglob("*") if file.is_file()}
            self.assertEqual(files, self.files)
            self.assertEqual(projection.render(self.source, self.commit, self.policy), files)
            with self.assertRaises(FileExistsError):
                projection.project(projection.ROOT, self.commit, output, self.policy)
            self.assertEqual((output / "projection.json").read_bytes(), files["projection.json"])
            for manifest in sorted(output.glob("*/Cargo.toml")):
                result = subprocess.run(
                    ["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1", "--manifest-path", manifest],
                    cwd=output, check=True, capture_output=True,
                )
                package, = json.loads(result.stdout)["packages"]
                self.assertEqual(package["name"], manifest.parent.name)
                self.assertEqual(package["features"], {})
                self.assertTrue(all(dep["kind"] is None and dep["source"] == projection.REGISTRY
                                    for dep in package["dependencies"]))
                if package["name"] == "exacopy":
                    self.assertEqual({target["name"] for target in package["targets"]}, {"exacopy_cli", "exacopy"})


if __name__ == "__main__":
    unittest.main()

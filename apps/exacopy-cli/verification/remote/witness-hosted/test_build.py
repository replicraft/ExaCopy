"""Portable selector, receipt and custody controls for the witness libtest build."""

import json
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build


class BuildControls(unittest.TestCase):
    def test_selects_only_fresh_compiler_reported_library_test(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            triple = "x86_64-unknown-linux-gnu"
            release = target / triple / "release"
            output = release / "deps/exacopy_cli-aabbccddeeff0011"
            output.parent.mkdir(parents=True)
            output.touch()
            log = root / "build.log"
            artifact = {
                "reason": "compiler-artifact",
                "package_id": f"path+{(root / build.CLI).as_uri()}#exacopy-cli@0.1.0",
                "manifest_path": str(root / build.CLI / "Cargo.toml"),
                "target": {
                    "kind": ["lib"], "name": "exacopy_cli",
                    "src_path": str(root / build.CLI / "src/lib.rs"),
                },
                "executable": str(output),
                "filenames": [str(output)],
                "features": ["experimental-ssh-capture"],
                "fresh": False,
                "profile": {"test": True},
            }

            def select(*records):
                log.write_text("\n".join(json.dumps(row) for row in records) + "\n")
                return build.cargo_libtest(log, root, target, build.native.DIRECT, triple)

            self.assertEqual(select(artifact), (output, ["experimental-ssh-capture"]))
            for changed in (
                {"fresh": True}, {"profile": {"test": False}},
                {"features": ["experimental-ssh-capture", "experimental-ssh-wireguard"]},
                {"target": {"kind": ["bin"], "name": "exacopy"}},
                {"package_id": "path+file:///elsewhere#exacopy-cli@0.1.0"},
                {"manifest_path": str(root / "Cargo.toml")},
                {"filenames": []},
            ):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    select(artifact | changed)
            with self.assertRaises(ValueError):
                select(artifact, artifact)

            # Same layout as the retained Cargo 1.100 hosted sync libtest, with
            # this package and a release build substituted for its debug build.
            hosted = release / "build/exacopy-cli/10b2d13251105b76/out/exacopy_cli-10b2d13251105b76"
            hosted.parent.mkdir(parents=True)
            hosted.touch()
            recorded = artifact | {
                "package_id": f"path+{(root / build.CLI).as_uri()}#0.1.0",
                "executable": str(hosted), "filenames": [str(hosted)],
            }
            self.assertEqual(select(recorded), (hosted, ["experimental-ssh-capture"]))
            for wrong in (
                release / hosted.relative_to(release).with_name("exacopy-10b2d13251105b76"),
                release / "build/foreign/10b2d13251105b76/out/exacopy_cli-10b2d13251105b76",
                target / "aarch64-unknown-linux-gnu/release/deps/exacopy_cli-10b2d13251105b76",
            ):
                wrong.parent.mkdir(parents=True, exist_ok=True)
                wrong.touch()
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    select(recorded | {"executable": str(wrong), "filenames": [str(wrong)]})
            alias = hosted.with_name("exacopy_cli-aabbccddeeff0011")
            alias.symlink_to(hosted)
            with self.assertRaises(ValueError):
                select(recorded | {"executable": str(alias), "filenames": [str(alias)]})

    def test_facts_bind_independent_digest_and_exact_held_root(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "facts.log"
            digest = "ab" * 32
            observed = {
                "architecture": "x86_64", "device": "17", "inode": "19",
                "effective_uid": os.geteuid(), "effective_gid": os.getegid(),
                "boot_id_hex": "11" * 16, "mount_namespace": "4", "mount_id": "5",
                "unique_mount": "6", "kernel_release_hex": "0a",
                "kernel_build_hex": "0b", "mount_record_hex": "0c",
            }

            def select(destination, running_digest=digest, *, repeat=False, separated=True):
                payload = build.FACTS_MARKER + json.dumps({
                    "build_blake3_derive_key": running_digest, "destination": destination,
                }).encode() + b"\n"
                # Serial --nocapture prints the test name before the test body.
                # The Rust fixture explicitly prints a newline before its marker.
                prefix = f"running 1 test\ntest {build.SELECTOR} ... ".encode()
                framed = prefix + (b"\n" if separated else b"") + payload + (payload if repeat else b"") + b"ok\n"
                log.write_bytes(framed)
                with patch.object(build.os, "uname", return_value=SimpleNamespace(machine="x86_64")):
                    return build.read_facts(log, (17, 19), digest)

            self.assertEqual(select(observed)["destination"], observed)
            with self.assertRaises(ValueError):
                select(observed, "aa" * 32)
            with self.assertRaises(ValueError):
                select(observed | {"inode": "20"})
            with self.assertRaises(ValueError):
                select(observed, repeat=True)
            with self.assertRaises(ValueError):
                select(observed, separated=False)

    def test_owned_directory_refuses_symlink_and_open_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(build.owned_directory(root), (root.stat().st_dev, root.stat().st_ino))
            child = root / "child"
            child.mkdir(mode=0o755)
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            for path in (child, alias):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    build.owned_directory(path)

    def test_report_creation_is_owner_only_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report = root / "manifest.json"
            build.write_owner_json(report, {"status": "built"})
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                build.write_owner_json(report, {"status": "foreign"})
            self.assertEqual(json.loads(report.read_bytes()), {"status": "built"})

    def test_digest_tool_pin_is_required_before_spawn(self):
        with patch.object(build.native, "logged_command", side_effect=AssertionError("spawn")):
            with self.assertRaisesRegex(ValueError, "approved digest-tool"):
                build.derived_build(None, None, None, None, None, {})


if __name__ == "__main__":
    unittest.main()

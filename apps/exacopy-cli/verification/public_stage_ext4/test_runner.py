"""Portable guard controls for the standalone public-stage fixture runner."""

import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import run


class RunnerTests(unittest.TestCase):
    def test_profile_and_input_inventory_exist(self):
        files = run.inputs()
        self.assertIn("apps/exacopy-cli/" + run.SOURCE, files)

    def test_only_exact_single_passing_case_and_cleanup_marker_count(self):
        def output(case=run.CASE, markers=1, count=1):
            return (
                f"test {case} ... ok\n"
                + (run.MARKER + "\n") * markers
                + f"test result: ok. {count} passed; 0 failed; 0 ignored; "
                  "0 measured; 30 filtered out; finished in 0.01s\n"
            )

        run.check_run(output())
        for bad in (output(case="other"), output(markers=0), output(markers=2), output(count=2)):
            with self.assertRaises(ValueError):
                run.check_run(bad)

    def test_additional_cargo_config_and_environment_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cargo_home = root / "cache"
            cargo_home.mkdir()
            selected = {"CARGO_HOME": str(cargo_home)}
            with patch.object(run, "ROOT", root), patch.dict(os.environ, selected, clear=True):
                run.check_cargo_environment()
                with patch.dict(os.environ, {"CARGO_BUILD_RUSTFLAGS": "-Dwarnings"}):
                    with self.assertRaisesRegex(ValueError, "override present"):
                        run.check_cargo_environment()
                (cargo_home / "config.toml").touch()
                with self.assertRaisesRegex(ValueError, "configuration present"):
                    run.check_cargo_environment()

    def test_artifact_must_match_package_and_stay_under_held_build_root(self):
        version = tomllib.loads((run.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / "target" / "libtest"
            binary.parent.mkdir()
            binary.touch()
            row = {
                "reason": "compiler-artifact", "package_id": f"path+{run.PACKAGE.as_uri()}#{version}",
                "manifest_path": str(run.PACKAGE / "Cargo.toml"), "profile": {"test": True},
                "features": [], "fresh": False, "executable": str(binary),
                "target": {"name": "exacopy_cli", "kind": ["lib"], "crate_types": ["lib"],
                           "src_path": str(run.PACKAGE / "src/lib.rs"), "edition": "2024"},
            }
            self.assertEqual(run.artifact(json.dumps(row), binary.parent), binary)
            for bad in (
                {**row, "package_id": "other"},
                {**row, "features": ["experimental-ssh-capture"]},
                {**row, "executable": str(root / "outside")},
                {**row, "target": {**row["target"], "kind": ["bin"]}},
            ):
                with self.assertRaises(ValueError):
                    run.artifact(json.dumps(bad), binary.parent)
            with self.assertRaises(ValueError):
                run.artifact("\n".join([json.dumps(row)] * 2), binary.parent)


if __name__ == "__main__":
    unittest.main()

"""Portable guard controls for the standalone public-stage fixture runner."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import run


class RunnerTests(unittest.TestCase):
    def test_profile_and_input_inventory_exist(self):
        files = run.inputs()
        self.assertIn("apps/exacopy-cli/" + run.SOURCE, files)
        fault = "apps/exacopy-cli/src/assembly/linux/public_stage/tests/late_journal.rs"
        self.assertEqual(files[fault], hashlib.sha256((run.ROOT / fault).read_bytes()).hexdigest())
        component = "apps/exacopy-cli/verification/public_stage_ext4/checked_component.rs"
        self.assertEqual(files[component], hashlib.sha256((run.ROOT / component).read_bytes()).hexdigest())
        helper = run.components.COVERAGE_HELPER
        path = helper.relative_to(run.ROOT).as_posix()
        digest = hashlib.sha256(helper.read_bytes()).hexdigest()
        self.assertEqual(files[path], digest)
        self.assertEqual(run.components.inputs()[path], digest)

    def test_dynamic_load_from_an_isolated_working_directory(self):
        probe = """
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("public_stage_probe", sys.argv[1])
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
components = runner.components
helper = components.coverage_profile
assert Path(helper.__file__) == runner.COMPONENT_DIR / "coverage_profile.py"
assert sys.modules[helper.__name__] is helper
assert runner.COMPONENT_DIR not in map(Path, sys.path)
"""
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-Werror", "-c", probe, str(run.HERE / "run.py")],
                cwd=directory, capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

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

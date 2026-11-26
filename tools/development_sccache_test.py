"""Controls for the optional development compiler cache."""

from pathlib import Path
import tempfile
import tomllib
import unittest

from development import sccache


class SccacheSupportTests(unittest.TestCase):
    def test_cargo_arguments_keep_locked_dev_features_and_never_select_release(self):
        self.assertEqual(
            sccache.cargo_command(["--", "build", "--locked", "-F", "example"], False),
            ["cargo", "build", "--profile", "dev", "--locked", "-F", "example"],
        )
        self.assertEqual(
            sccache.cargo_command(["check", "--all-targets"], True),
            ["cargo", "+1.100.0", "check", "--profile", "dev", "--all-targets"],
        )
        for args in (
            [], ["nextest", "run"], ["test"], ["run"], ["build", "-r"],
            ["check", "--release"], ["build", "--profile=release"],
            ["build", "--config", 'build.rustc-wrapper="elsewhere"'],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                sccache.cargo_command(args, False)

    def test_cache_roots_are_scoped_to_supported_local_or_ci_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            env = {"RUNNER_TEMP": str(root)}
            self.assertEqual(
                sccache.cache_root(root, True, env, "linux", "x86_64"), root / "exacopy-sccache",
            )
            self.assertEqual(sccache.cache_root(root, False, {}, "darwin", "arm64"), root / "target/sccache")
            for ci, environ, system, machine in (
                (True, {}, "linux", "x86_64"), (True, env, "linux", "arm64"),
                (True, env, "darwin", "x86_64"), (False, {}, "win32", "x86_64"),
            ):
                with self.subTest(ci=ci, system=system, machine=machine), self.assertRaises(ValueError):
                    sccache.cache_root(root, ci, environ, system, machine)

    def test_scoped_environment_replaces_ambient_wrapper_cache_and_network_settings(self):
        ambient = {
            "RUSTC": "/compiler", "RUSTC_WRAPPER": "/other-wrapper",
            "RUSTC_WORKSPACE_WRAPPER": "/workspace-wrapper", "RUSTFLAGS": "-C opt-level=1",
            "CARGO_INCREMENTAL": "1", "SCCACHE_GHA_ENABLED": "true",
            "SCCACHE_SERVER_UDS": "/tmp/foreign", "SCCACHE_SERVER_PORT": "4226",
            "SCCACHE_CONF": "/remote/config",
        }
        scope = sccache.scoped_environment(ambient, Path("/tool/sccache"), Path("/tmp/private"))
        self.assertNotIn("SCCACHE_GHA_ENABLED", scope)
        self.assertEqual(scope["SCCACHE_CONF"], "/tmp/private/config.toml")
        self.assertEqual(scope["SCCACHE_SERVER_UDS"], "/tmp/private/s")
        self.assertEqual(scope["SCCACHE_SERVER_PORT"], "0")
        self.assertEqual(scope["RUSTC_WRAPPER"], "/tool/sccache")
        self.assertEqual(scope["RUSTC_WORKSPACE_WRAPPER"], "")
        self.assertEqual(scope["CARGO_INCREMENTAL"], "0")
        self.assertEqual(scope["RUSTFLAGS"], ambient["RUSTFLAGS"])
        self.assertEqual(scope["RUSTC"], ambient["RUSTC"])
        self.assertEqual(ambient["SCCACHE_SERVER_UDS"], "/tmp/foreign")

    @unittest.skipUnless(sccache.os.name == "posix", "requires directory symlinks and Unix file locks")
    def test_disk_cache_is_bounded_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            with sccache.locked_cache(parent / "cache") as cache:
                config = parent / "config.toml"
                sccache.configure(config, cache)
                self.assertEqual(tomllib.loads(config.read_text()), {
                    "cache": {"disk": {"dir": str(cache / "objects"), "size": 1024**3}},
                })
                with self.assertRaisesRegex(ValueError, "another ExaCopy"):
                    with sccache.locked_cache(parent / "cache"):
                        self.fail("a second server obtained the same cache")
            (parent / "foreign").mkdir()
            (parent / "alias").symlink_to(parent / "foreign", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "without symlinks"):
                with sccache.locked_cache(parent / "alias"):
                    self.fail("cache followed a redirected location")

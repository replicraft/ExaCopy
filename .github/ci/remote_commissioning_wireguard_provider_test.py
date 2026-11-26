import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import remote_commissioning_wireguard_provider as provider


RELEASE = "7.0.0-1020-azure"
BUILD = "#21~24.04.2-Ubuntu SMP PREEMPT Tue Nov 10 01:36:36 UTC 2026"
VERSION = "7.0.0-1020.21~24.04.2"
FACTS = provider.ProviderFacts
KERNEL_METADATA = Path("/lib/modules") / RELEASE / "modules.builtin"


class ProviderTests(unittest.TestCase):
    def test_provider_states_and_contradictions(self):
        for expected, facts in (
            ("built-in", FACTS("built-in", "present", "absent", "absent", "absent")),
            ("already-live", FACTS("module", "absent", "live", "live", "packaged")),
            ("already-live", FACTS("unknown", "unknown", "live", "live", "unknown")),
            ("packaged-but-unloaded", FACTS("module", "absent", "absent", "absent", "packaged")),
            ("absent", FACTS("disabled", "absent", "absent", "absent", "absent")),
            ("unknown", FACTS("unknown", "absent", "absent", "absent", "packaged")),
            ("unknown", FACTS("module", "absent", "live", "absent", "packaged")),
            ("unknown", FACTS("module", "absent", "absent", "live", "packaged")),
            ("unknown", FACTS("module", "absent", "transitional", "transitional", "packaged")),
            ("unknown", FACTS("disabled", "absent", "live", "live", "packaged")),
            ("unknown", FACTS("built-in", "present", "absent", "unknown", "absent")),
            ("unknown", FACTS("built-in", "absent", "absent", "absent", "absent")),
            ("unknown", FACTS("disabled", "absent", "absent", "absent", "packaged")),
        ):
            with self.subTest(expected=expected, facts=facts):
                self.assertEqual(provider.classify(facts), expected)

    def test_exact_package_version_from_measured_kernel(self):
        self.assertEqual(provider.kernel_package_version(RELEASE, BUILD), VERSION)
        self.assertEqual(
            provider.kernel_package_version(
                "7.0.0-1014-aws", "#14~24.04.1-Ubuntu SMP PREEMPT Fri Sep 18 21:24:59 UTC 2026",
            ),
            "7.0.0-1014.14~24.04.1",
        )
        self.assertIsNone(provider.kernel_package_version("7.0.0-1020-azure/..", BUILD))
        self.assertIsNone(provider.kernel_package_version(RELEASE, "#21-custom"))

    def test_parsers_use_exact_unique_records(self):
        self.assertEqual(provider.config_selection(b"# CONFIG_WIREGUARD is not set\n"), "disabled")
        self.assertEqual(provider.config_selection(b"CONFIG_WIREGUARD=y\nCONFIG_WIREGUARD=m\n"), "unknown")
        self.assertEqual(provider.config_selection(b"CONFIG_WIREGUARD_DEBUG=y\n"), "unknown")
        line = str(provider.MODULE).encode() + b"\n"
        self.assertEqual(provider.builtin_selection(line, RELEASE), "present")
        self.assertEqual(provider.builtin_selection(line * 2, RELEASE), "unknown")
        self.assertEqual(provider.builtin_selection(b"other/" + line, RELEASE), "absent")
        self.assertEqual(provider.module_listing(b"wireguard 81920 0 - Live 0x0\n"), "live")
        self.assertEqual(provider.module_listing(b"wireguard 81920 0 - Unloading 0x0\n"), "transitional")
        self.assertEqual(provider.module_listing(b"wireguard_bad 81920 0 - Live 0x0\n"), "absent")
        self.assertEqual(provider.module_listing(b"wireguard  {\n"), "unknown")
        self.assertEqual(provider.module_listing(b"wireguard 81920 0 - Live 0x0\n" * 2), "unknown")

    def test_exact_package_ownership_rejects_other_binary_or_build(self):
        pkg = f"linux-modules-{RELEASE}"
        listing = [f"{pkg}: {KERNEL_METADATA}"]
        for package_lines, installed_lines, expected, status in (
            (listing, [f"install ok installed\t{VERSION}\tamd64"], pkg, "verified"),
            (listing, [f"install ok installed\t{VERSION}\tarm64"], None, "installed-record-mismatch"),
            (listing, [f"deinstall ok config-files\t{VERSION}\tamd64"], None, "installed-record-mismatch"),
            (listing, ["install ok installed\t7.0.0-1020.20~24.04.2\tamd64"], None, "installed-record-mismatch"),
            (listing + listing, [], None, "ambiguous-owner-record"),
            ([f"unrelated: {KERNEL_METADATA}"], [], None, "package-not-admitted"),
            ([f"{pkg}: /usr/bin/other"], [], None, "owner-path-mismatch"),
        ):
            with self.subTest(installed=installed_lines, results=package_lines):
                with patch.object(provider, "dpkg_query", side_effect=[package_lines, installed_lines]):
                    actual, detail = provider.package_owner(KERNEL_METADATA, RELEASE, VERSION)
                self.assertEqual(actual and actual["package"], expected)
                self.assertEqual(detail["status"], status)

    def test_package_query_failures_separate_phase_without_query_output(self):
        owner_args = [f"linux-modules-{RELEASE}: {KERNEL_METADATA}"]
        for error, status, extra in (
            (subprocess.CalledProcessError(1, ("hidden",), output=b"hidden"), "nonzero-exit", {"exit_status": 1}),
            (subprocess.TimeoutExpired(("hidden",), 5, output=b"hidden"), "timeout", {}),
            (provider.QueryRefusal("output-limit"), "output-limit", {}),
            (provider.QueryRefusal("non-ascii-output"), "non-ascii-output", {}),
            (provider.QueryRefusal("empty-output"), "empty-output", {}),
            (OSError(13, "hidden"), "io-error", {"errno": 13}),
        ):
            for phase, results in (("owner", [error]), ("installed", [owner_args, error])):
                with self.subTest(status=status, phase=phase), patch.object(provider, "dpkg_query", side_effect=results):
                    package, detail = provider.package_owner(KERNEL_METADATA, RELEASE, VERSION)
                    self.assertIsNone(package)
                    self.assertEqual(detail, {"path": str(KERNEL_METADATA), "phase": phase, "status": status} | extra)

    def test_file_and_package_statuses_are_independent(self):
        data = b"CONFIG_WIREGUARD=m\n"
        for error, reason in (
            (FileNotFoundError(), "missing"),
            (provider.FileRefusal("extent-limit"), "extent-limit"),
            (provider.FileRefusal("changed-during-read"), "changed-during-read"),
            (OSError(13, "hidden"), "io-error"),
        ):
            with self.subTest(reason=reason), patch.object(provider, "read_root_file", side_effect=error):
                detail = provider.read_observation(KERNEL_METADATA, 128, provider.config_selection)
                self.assertEqual(detail["read_status"], reason)
                self.assertNotIn("sha256", detail)
        with (
            patch.object(provider, "read_root_file", return_value=data),
            patch.object(provider, "package_owner") as search,
        ):
            detail = provider.from_kernel_package(KERNEL_METADATA, RELEASE, None, 128, provider.config_selection)
            self.assertEqual(detail, {
                "status": "unknown", "read_status": "read", "parsed_status": "module",
                "sha256": provider.digest(data), "package_status": "skipped-unbound-image",
            })
            search.assert_not_called()

    def test_exact_image_refusal_is_reported_and_classifier_remains_unknown(self):
        image = Path("/boot") / f"vmlinuz-{RELEASE}"
        data = b"CONFIG_WIREGUARD=m\n"
        expected = {"path": str(image), "phase": "owner", "status": "nonzero-exit", "exit_status": 1}
        with (
            patch.object(provider, "read_observation", side_effect=[
                {"status": "absent"},
                {"status": "module", "read_status": "read", "parsed_status": "module", "sha256": provider.digest(data)},
                {"status": "absent", "read_status": "read", "parsed_status": "absent", "sha256": provider.digest(b"")},
                {"status": "missing"}, {"status": "absent"},
            ]),
            patch.object(provider, "image_path_observation", return_value={"status": "observed"}),
            patch.object(provider, "package_owner", return_value=(None, expected)) as owner,
            patch.object(provider, "installed_module", return_value={"status": "unknown"}),
        ):
            status, report = provider.observe_provider(RELEASE, BUILD)
        owner.assert_called_once_with(image, RELEASE, VERSION)
        self.assertEqual(status, "unknown")
        self.assertIsNone(report["booted_kernel_package"])
        self.assertEqual(report["booted_kernel_package_diagnostic"], expected | {
            "expected_version": VERSION, "file": {"status": "observed"},
        })
        self.assertEqual(report["config"]["status"], "unknown")
        self.assertEqual(report["config"]["parsed_status"], "module")

    def test_package_query_handles_exact_bound_and_discards_stderr(self):
        source = "import os; os.write(2, b'e' * 100000); os.write(1, b'a' * 4096)"
        with patch.object(provider, "DPKG_QUERY", sys.executable):
            self.assertEqual(provider.dpkg_query("-c", source), ["a" * 4096])

    def test_package_query_records_real_empty_invalid_and_nonzero_outcomes(self):
        for source, expected in (
            ("pass", {"status": "empty-output"}),
            ("import os; os.write(1, bytes([255]))", {"status": "non-ascii-output"}),
            ("import sys; sys.exit(9)", {"status": "nonzero-exit", "exit_status": 9}),
        ):
            with self.subTest(expected=expected), patch.object(provider, "DPKG_QUERY", sys.executable):
                self.assertEqual(provider.package_query("owner", "-c", source), (None, {"phase": "owner"} | expected))

        with patch.object(provider, "dpkg_query", side_effect=RuntimeError("cannot confirm package query exit")):
            with self.assertRaisesRegex(RuntimeError, "cannot confirm package query exit"):
                provider.package_owner(KERNEL_METADATA, RELEASE, VERSION)

    def test_package_query_kills_and_reaps_flooding_or_stalled_child(self):
        cases = (
            ("import os, time; os.write(1, b'a' * 4097); time.sleep(30)", ValueError),
            ("import time; time.sleep(30)", subprocess.TimeoutExpired),
            ("import os, time; os.close(1); time.sleep(30)", subprocess.TimeoutExpired),
        )
        for source, error in cases:
            with self.subTest(source=source):
                processes = []
                start = subprocess.Popen

                def tracked_start(*args, **kwargs):
                    process = start(*args, **kwargs)
                    processes.append(process)
                    return process

                with (
                    patch.object(provider, "DPKG_QUERY", sys.executable),
                    patch.object(provider, "PACKAGE_QUERY_SECONDS", 2),
                    patch.object(provider.subprocess, "Popen", side_effect=tracked_start),
                ):
                    with self.assertRaises(error):
                        provider.dpkg_query("-c", source)
                self.assertEqual(len(processes), 1)
                self.assertEqual(processes[0].returncode, -signal.SIGKILL)
                self.assertTrue(processes[0].stdout.closed)

    def test_partial_report_write_never_publishes_or_leaves_candidate(self):
        with TemporaryDirectory() as scratch:
            directory = Path(scratch)
            open_stream = os.fdopen

            class BrokenWrite:
                def __init__(self, fd, *args, **kwargs):
                    self.stream = open_stream(fd, *args, **kwargs)

                def __enter__(self):
                    return self

                def __exit__(self, *failure):
                    self.stream.close()

                def write(self, text):
                    self.stream.write(text[:5])
                    self.stream.flush()
                    raise OSError("injected report write failure")

            with patch.object(provider.os, "fdopen", side_effect=BrokenWrite):
                with self.assertRaisesRegex(OSError, "injected report write failure"):
                    provider.write_report(directory, {"provider": "unknown"})
            self.assertEqual(list(directory.iterdir()), [])

    def test_report_is_complete_before_final_name_appears(self):
        with TemporaryDirectory() as scratch:
            directory = Path(scratch)
            final = directory / "provider.json"
            selected = {"provider": "unknown", "qualified": False}
            replace = Path.replace

            def publish(pending, target):
                self.assertEqual(target, final)
                self.assertFalse(final.exists())
                self.assertEqual(json.loads(pending.read_text()), selected)
                return replace(pending, target)

            with patch.object(Path, "replace", autospec=True, side_effect=publish):
                provider.write_report(directory, selected)
            self.assertEqual(list(directory.iterdir()), [final])
            self.assertEqual(json.loads(final.read_text()), selected)

    def test_disk_candidates_reject_multiple_compressions(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            module = root / provider.MODULE
            module.parent.mkdir(parents=True)
            self.assertEqual(provider.installed_module(root, RELEASE, VERSION), {"status": "absent", "read_status": "no-candidate"})
            compressed = module.with_suffix(".ko.zst")
            compressed.touch()
            with patch.object(provider, "from_kernel_package", return_value={"status": "packaged"}) as check:
                self.assertEqual(provider.installed_module(root, RELEASE, VERSION), {"status": "packaged"})
                self.assertEqual(check.call_args.args[0], compressed)
            module.touch()
            self.assertEqual(provider.installed_module(root, RELEASE, VERSION), {"status": "unknown", "read_status": "multiple-candidates"})

    def test_inconsistent_observed_module_history_is_unknown(self):
        with (
            patch.object(provider, "image_path_observation", return_value={"status": "observed"}),
            patch.object(provider, "read_observation", side_effect=[
                {"status": "live"}, {"status": "live"}, {"status": "absent"},
            ]),
            patch.object(provider, "package_owner", return_value=({"package": "kernel", "version": VERSION}, {"status": "verified"})),
            patch.object(provider, "from_kernel_package", side_effect=[
                {"status": "module"}, {"status": "absent"},
            ]),
            patch.object(provider, "installed_module", return_value={"status": "packaged"}),
        ):
            status, _ = provider.observe_provider(RELEASE, BUILD)
        self.assertEqual(status, "unknown")

    def test_portable_entrypoint_only_writes_fresh_owned_report(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            selected = {"provider": "unknown", "qualified": False}
            with (
                patch.object(provider, "hosted_admission", return_value=root),
                patch.object(provider, "report", return_value=selected),
            ):
                with patch.object(os, "umask", wraps=os.umask) as umask:
                    provider.main()
                    umask.assert_not_called()
                with self.assertRaises(FileExistsError):
                    provider.main()
            path = root / provider.REPORT / "provider.json"
            self.assertEqual(json.loads(path.read_text()), selected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_local_or_unmatched_host_is_refused_before_observations(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(provider, "read_root_file") as reader:
            with self.assertRaises(ValueError):
                provider.hosted_admission()
            reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()

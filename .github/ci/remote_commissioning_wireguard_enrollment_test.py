from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import lzma
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import remote_commissioning_wireguard_enrollment as scanner
import wireguard_enrollment_archive as archive

AWS, AZURE = scanner.CANDIDATES
REVISION = "a" * 40
NOW = datetime(2026, 11, 26, 14, 0, tzinfo=timezone.utc)


def release(index):
    return f"""Origin: Ubuntu
Label: Ubuntu
Suite: noble-security
Codename: noble
Date: Thu, 26 Nov 2026 13:55:00 UTC
Valid-Until: Fri, 27 Nov 2026 13:55:00 UTC
Architectures: amd64 arm64
Components: main restricted
Acquire-By-Hash: yes
SHA256:
 {index.sha256} {index.size} {archive.INDEX}
""".encode()


def stanza(name, version, filename):
    return f"""Package: {name}
Version: {version}
Architecture: amd64
Filename: {filename}
Size: 12345
SHA256: {"c" * 64}
Description: exact test record
 with a continuation

""".encode()


def observation(candidate):
    values = candidate.known_hashes or ("e" * 64, "f" * 64, "0" * 64)
    return {
        "schema": scanner.provider.SCHEMA, "provider": "packaged-but-unloaded", "revision": REVISION,
        "kernel": {"architecture": "x86_64", "release": candidate.release, "build": candidate.build,
                   "boot_id": "899f4576-2392-41dd-854a-d9d2387145ad"},
        "observations": {
            "booted_kernel_package": candidate.package_record(candidate.image()),
            "module_listing_before": {"status": "absent"},
            "module_listing_after": {"status": "absent"},
            "module_initstate": {"status": "missing"},
        } | {
            label: candidate.package_record(candidate.module_package()) | {"status": status, "sha256": digest}
            for label, status, digest in zip(
                ("config", "builtin_inventory", "module_file"), ("module", "absent", "packaged"), values,
            )
        },
    }


class EnrollmentControls(unittest.TestCase):
    def test_closed_boots_exact_provider_fingerprints_and_no_uname_only_authority(self):
        for candidate in scanner.CANDIDATES:
            report = observation(candidate)
            self.assertEqual(scanner.selected(report), candidate)
            self.assertEqual(len(scanner.provider_hashes(report, candidate, REVISION)), 3)
            for key, update in (("provider", "unknown"), ("revision", "b" * 40), ("schema", "v1")):
                with self.subTest(candidate=candidate.tag, field=key), self.assertRaises(scanner.Blocked):
                    scanner.provider_hashes(report | {key: update}, candidate, REVISION)
        changed = deepcopy(observation(AWS))
        changed["observations"]["config"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(scanner.Blocked, "independent"):
            scanner.provider_hashes(changed, AWS, REVISION)
        with self.assertRaises(scanner.Blocked):
            scanner.provider_hashes(observation(AZURE) | {"observations": {}}, AZURE, REVISION)
        changed = deepcopy(observation(AZURE))
        changed["kernel"]["build"] += "-foreign"
        with self.assertRaises(scanner.Blocked):
            scanner.selected(changed)

    def test_release_requires_exact_signed_geometry_and_valid_unique_index(self):
        expected = archive.Extent(100, "a" * 64)
        parsed = release(expected)
        self.assertEqual(archive.release_index(parsed, NOW), expected)
        for invalid in (
            parsed.replace(b"Suite: noble-security", b"Suite: noble-updates"),
            parsed.replace(b"Origin: Ubuntu", b"Origin: foreign"),
            parsed.replace(b"Acquire-By-Hash: yes", b"Acquire-By-Hash: no"),
            parsed.replace(b"Thu, 26 Nov 2026", b"Mon, 16 Nov 2026"),
            parsed.replace(b"Fri, 27 Nov 2026", b"Thu, 26 Nov 2026"),
            parsed + parsed.splitlines(keepends=True)[-1],
            parsed.replace(b" 100 main/", b" 999999999 main/"),
            parsed.replace(b"main/binary-amd64", b"universe/binary-amd64"),
        ):
            with self.subTest(record=invalid), self.assertRaises(scanner.Blocked):
                archive.release_index(invalid, NOW)

    def test_versions_and_archive_identity_are_exact_unique_and_bounded(self):
        expected = AWS.expected_packages()
        valid = b"".join(stanza(name, *values) for name, values in expected.items())
        with tempfile.TemporaryDirectory() as scratch:
            index = Path(scratch) / "Packages.xz"
            for content in (
                valid + valid, valid.replace(b"amd64\nFilename", b"arm64\nFilename", 1),
                valid.replace(b"/linux-signed-aws-7.0/", b"/anywhere-else/", 1),
                valid.replace(b"Size: 12345", b"Size: 999999999", 1),
                valid.replace(b"~24.04.1\n", b"~24.04.2\n", 1),
            ):
                index.write_bytes(lzma.compress(content))
                with self.assertRaises(scanner.Blocked):
                    archive.package_rows(index, expected)
            index.write_bytes(lzma.compress(valid))
            actual = archive.package_rows(index, expected)
            self.assertEqual(set(actual), set(expected))
            self.assertEqual(actual[AWS.module_package()]["sha256"], "c" * 64)
            with patch.object(archive, "INDEX_PLAIN_MAX", 100):
                with self.assertRaises(scanner.Blocked):
                    archive.package_rows(index, expected)
            expected_content = archive.Extent(index.stat().st_size, sha256(index.read_bytes()).hexdigest())
            archive.verify_blob(index, expected_content)
            with self.assertRaises(scanner.Blocked):
                archive.verify_blob(index, archive.Extent(expected_content.size, "f" * 64))

    def test_failed_signature_never_parses_or_fetches_index(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            with (
                patch.object(archive, "fetch") as fetch,
                patch.object(archive, "checked_hash", return_value="a" * 64),
                patch.object(archive, "bounded", side_effect=scanner.Blocked("signature-refused")) as bounded,
                patch.object(archive, "release_index") as parse,
            ):
                with self.assertRaisesRegex(scanner.Blocked, "signature-refused"):
                    archive.signed_index(root, {}, AWS.expected_packages())
                command = bounded.call_args.args[0]
                self.assertEqual(command[0], archive.GPGV)
                self.assertIn(archive.KEYRING, command)
                self.assertEqual(command[-2:], [root / "Release.gpg", root / "Release"])
                self.assertEqual(fetch.call_count, 2)
                parse.assert_not_called()

    def test_signed_catalog_records_exact_file_custody_failure_before_gpgv(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            keyring = root / "keyring"
            keyring.write_bytes(b"archive-keyring")
            os.link(keyring, root / "second-link")
            evidence = {}
            with (
                patch.object(archive, "KEYRING", keyring),
                patch.object(archive, "fetch") as fetch,
                patch.object(archive, "bounded") as command,
            ):
                with self.assertRaises(scanner.Blocked):
                    archive.signed_index(root, evidence, AWS.expected_packages())
            self.assertEqual(fetch.call_count, 2)
            command.assert_not_called()
            steps = evidence["canonical_steps"]
            self.assertEqual(steps["release-download"]["status"], "observed")
            self.assertEqual(steps["release-signature-download"]["status"], "observed")
            self.assertEqual(steps["ubuntu-archive-keyring"]["status"], "blocked")
            self.assertEqual(steps["ubuntu-archive-keyring"]["file"]["links"], 2)
            self.assertEqual(steps["ubuntu-archive-keyring"]["file"]["bytes"], 15)
            self.assertNotIn("canonical", evidence)

    def test_zero_length_release_has_distinct_archive_phase_evidence(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            evidence = {}

            def empty(_url, path, _seconds, maximum):
                path.touch()
                archive.regular(path, os.geteuid(), maximum)

            with patch.object(archive, "fetch", side_effect=empty), patch.object(archive, "bounded") as command:
                with self.assertRaises(scanner.Blocked):
                    archive.signed_index(root, evidence, AWS.expected_packages())
            step = evidence["canonical_steps"]["release-download"]
            self.assertEqual(step["status"], "blocked")
            self.assertEqual(step["file"]["bytes"], 0)
            self.assertTrue(step["file"]["owner_matches"])
            self.assertEqual(set(evidence["canonical_steps"]), {"release-download"})
            command.assert_not_called()

    def test_inherited_group_writable_capture_is_recorded_not_admitted(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            fake = root / "synthetic-output-only"
            fake.write_text("#!/bin/sh\nprintf 'synthetic release'\n", encoding="ascii")
            fake.chmod(0o700)
            evidence = {}
            previous = os.umask(0o002)
            try:
                with patch.object(archive, "CURL", str(fake)):
                    with self.assertRaises(scanner.Blocked):
                        archive.signed_index(root, evidence, AWS.expected_packages())
            finally:
                os.umask(previous)
            step = evidence["canonical_steps"]["release-download"]
            self.assertEqual(step["status"], "blocked")
            self.assertEqual(step["file"]["mode"], "0664")
            self.assertEqual(step["file"]["bytes"], len("synthetic release"))
            self.assertNotIn("canonical", evidence)

    def test_native_kmod_only_exact_candidate_paths_and_topology(self):
        def module(name, deps):
            return scanner.parsing.Module(name, "a" * 64, tuple(deps), AWS.release + " SMP", "Ubuntu")

        modules = {"wireguard": module("wireguard", ("udp_tunnel",)), "udp_tunnel": module("udp_tunnel", ())}
        paths = AWS.modules()
        plan = f"insmod {paths['udp_tunnel']}\ninsmod {paths['wireguard']}\n".encode()
        self.assertEqual(scanner.order_modules(AWS, modules, plan), ["udp_tunnel", "wireguard"])
        for invalid in (
            plan.replace(b"1018-aws", b"1020-azure"), plan.replace(b"insmod", b"install", 1),
            plan.replace(b".ko.zst\n", b".ko.zst any=1\n", 1),
            b"\n".join(reversed(plan.strip().splitlines())), plan + plan,
        ):
            with self.assertRaises(scanner.Blocked):
                scanner.order_modules(AWS, modules, invalid)

    def test_module_source_requires_paired_report_before_kmod_probe(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch) / "work"
            report = Path(scratch) / "report"
            work.mkdir()
            report.mkdir()
            evidence = {}
            initial = observation(AWS) | {"provider": "unknown"}
            with (
                patch.object(scanner.provider, "report", return_value=initial),
                patch.object(scanner, "same_boot"),
                patch.object(scanner.parsing, "checked_hash"),
                patch.object(Path, "resolve", return_value=Path("/synthetic/tool")),
                patch.object(archive, "signed_index", return_value=({}, {})) as signed,
                patch.object(scanner, "check_selected_archive") as probe,
            ):
                with self.assertRaisesRegex(scanner.Blocked, "ownership or unloaded"):
                    scanner.collect(work, report, {"revision": REVISION}, evidence)
                self.assertEqual(evidence["provider_observation"], initial)
                signed.assert_called_once()
                probe.assert_not_called()

    def test_wrong_workflow_ref_refuses_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            with (
                patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": "foreign", "GITHUB_SHA": REVISION}),
                patch.object(scanner.provider, "hosted_admission", return_value=root),
                patch.object(scanner.direct, "hosted_parent", return_value=root),
                patch.object(scanner, "collect") as collect,
            ):
                with self.assertRaises(scanner.Blocked):
                    scanner.main()
                self.assertFalse((root / scanner.JOB).exists())
                collect.assert_not_called()

    def test_pending_record_precedes_all_job_directories(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            mkdir = Path.mkdir

            def before_job(path, **options):
                if path != root / scanner.JOB:
                    return mkdir(path, **options)
                self.assertTrue((root / scanner.PENDING).is_file())
                raise OSError("injected pre-creation stop")

            with (
                patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": scanner.WORKFLOW_REF,
                                        "GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION}),
                patch.object(scanner.provider, "hosted_admission", return_value=root),
                patch.object(scanner.direct, "hosted_parent", return_value=root),
                patch.object(scanner.direct.native, "source_identity", return_value={"revision": REVISION}),
                patch.object(scanner.signal, "signal"),
                patch.object(Path, "mkdir", before_job),
                patch.object(scanner, "collect") as collect,
            ):
                with self.assertRaisesRegex(OSError, "pre-creation stop"):
                    scanner.main()
                self.assertFalse((root / scanner.JOB).exists())
                collect.assert_not_called()

    def test_confirmed_collection_disposes_scratch_and_keeps_nonqualifying_report(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            seen = {}

            def collect(work, report, source, evidence):
                seen.update(evidence)
                self.assertTrue((root / scanner.PENDING).is_file())
                self.assertTrue((report / "cleanup-unconfirmed.json").is_file())
                (work / "owned-archive").write_bytes(b"temporary")

            with (
                patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": scanner.WORKFLOW_REF,
                                        "GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION}),
                patch.object(scanner.provider, "hosted_admission", return_value=root),
                patch.object(scanner.direct, "hosted_parent", return_value=root),
                patch.object(scanner.direct.native, "source_identity", return_value={"revision": REVISION}),
                patch.object(scanner.signal, "signal"),
                patch.object(scanner, "collect", side_effect=collect),
            ):
                self.assertEqual(scanner.main(), 0)
                self.assertFalse((root / scanner.JOB / "private").exists())
                self.assertFalse((root / scanner.PENDING).exists())
                report = (root / scanner.JOB / "report/provider.json").read_text()
                self.assertIn('"status": "observed"', report)
                self.assertIn('"qualified": false', report)
                self.assertIs(seen["load_attempted"], False)

    def test_unconfirmed_child_preserves_exact_job_scratch_and_blocks(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            with (
                patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": scanner.WORKFLOW_REF,
                                        "GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION}),
                patch.object(scanner.provider, "hosted_admission", return_value=root),
                patch.object(scanner.direct, "hosted_parent", return_value=root),
                patch.object(scanner.direct.native, "source_identity", return_value={"revision": REVISION}),
                patch.object(scanner.signal, "signal"),
                patch.object(scanner, "collect", side_effect=scanner.CleanupUnconfirmed("sticky")),
            ):
                self.assertEqual(scanner.main(), 77)
                self.assertTrue((root / scanner.JOB / "private").exists())
                report = (root / scanner.JOB / "report/provider.json").read_text()
                self.assertTrue((root / scanner.PENDING).is_file())
                self.assertIn('"cleanup_unconfirmed": true', report)
                self.assertIn('"load_attempted": false', report)


if __name__ == "__main__":
    unittest.main()

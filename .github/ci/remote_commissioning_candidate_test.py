"""Portable controls for exact preview import and executable custody."""

import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import remote_commissioning_candidate as candidate
import preview_release_notices

SOURCE = {"revision": "a" * 40, "git_tree": "b" * 40, "lock_sha256": "c" * 64}
DIRECT = candidate.native.DIRECT
EMBEDDED = candidate.native.EMBEDDED


def encode(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def elf_bytes(machine=62, osabi=0):
    header = bytearray(candidate.ELF_HEADER)
    header[:7] = b"\x7fELF\x02\x01\x01"
    header[7] = osabi
    struct.pack_into("<HHI", header, 16, 3, machine, 1)
    struct.pack_into("<H", header, 52, candidate.ELF_HEADER)
    return bytes(header) + b"portable fixture"


def record(path):
    data = path.read_bytes()
    return {"name": path.name, "sha256": candidate.sha256(data), "size": len(data)}


class CandidateFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="exacopy-remote-candidate-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.repo = self.root / "repo"
        actual_repo = candidate.native.REPO
        repository = patch.object(candidate.native, "REPO", self.repo)
        repository.start()
        self.addCleanup(repository.stop)
        for relative in (candidate.apfs_source.PIN, candidate.transport_source.PIN):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((actual_repo / relative).read_bytes())
        (self.repo / candidate.LICENSE).write_bytes(b"fixture license\n")
        self.intent = {
            "schema": candidate.REQUEST_SCHEMA, "intended_tag": candidate.TAG,
            "workspace_version": candidate.VERSION, "target": candidate.TARGET,
            "feature": candidate.FEATURES[-1], "nonce": "d" * 32,
        }
        self.intent_path = self.repo / candidate.REQUEST_PATH
        self.intent_path.parent.mkdir(parents=True)
        self.intent_path.write_bytes(encode(self.intent))
        self.input = self.root / candidate.INPUT_ROOT
        self.input.mkdir(mode=0o700)
        self.elf = elf_bytes()
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.binary = self.stage / "exacopy"
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.evidence = self.work / "build"

    def request(self, *, route=DIRECT, receipt_change=None):
        license_bytes = (self.repo / candidate.LICENSE).read_bytes()
        (self.input / candidate.LICENSE).write_bytes(license_bytes)
        path = self.input / candidate.ARCHIVE
        candidate.assets.write_archive(path, self.elf, license_bytes)
        producer = candidate.CandidateRequest(
            self.input, route, SOURCE["revision"], "73", "1", "123", "0" * 64, "1" * 64,
            record(path)["sha256"], candidate.sha256(self.intent_path.read_bytes()),
        )
        self.write_producer_receipt(path, producer)
        receipt_path = self.input / candidate.RECEIPT
        if receipt_change:
            receipt = json.loads(receipt_path.read_bytes())
            receipt_change(receipt)
            receipt_path.write_bytes(encode(receipt))
        (self.input / candidate.CHECKSUMS).write_text(
            "".join(
                f"{record(self.input / name)['sha256']}  {name}\n"
                for name in sorted(candidate.INVENTORY.keys() - {candidate.CHECKSUMS})
            ),
            encoding="ascii",
        )
        return candidate.CandidateRequest(
            **(vars(producer) | {"receipt_sha256": record(receipt_path)["sha256"]}),
        )

    def write_producer_receipt(self, archive, producer):
        build = self.root / "producer"
        compiled = build / "release/exacopy"
        compiled.parent.mkdir(parents=True)
        compiled.write_bytes(self.elf)
        transcript = build / "build.log"
        transcript.write_bytes(b"fixture compiler transcript\n")
        manifest = build / "result.json"
        manifest.write_bytes(encode({"fixture": "native producer build"}))
        observed = {
            "argv": [
                "cargo", "+1.100.0", "build", "--release", "--offline", "--locked",
                "--no-default-features", "-p", "exacopy-cli", "--bin", "exacopy",
                "--features", "experimental-ssh-wireguard", "--message-format=json-render-diagnostics",
            ],
            "build_log_sha256": record(transcript)["sha256"],
            "build_sha256": record(compiled)["sha256"], "build_size": len(self.elf),
            "compiled_features": ["experimental-ssh-capture", "experimental-ssh-wireguard"],
            "source_after": SOURCE,
        }
        floors = {"host_glibc": "glibc 2.35", "highest_imported_glibc": "2.34"}
        plan = {"source": SOURCE, "workflow": producer.workflow(), "request_sha256": producer.request_sha256}
        environment = {
            "GITHUB_WORKFLOW_REF": candidate.WORKFLOW_REF, "GITHUB_WORKFLOW_SHA": SOURCE["revision"],
            "GITHUB_RUN_ID": producer.run_id, "GITHUB_RUN_ATTEMPT": producer.run_attempt,
        }

        def write_sbom(_root, _env, output, *_args, **_kwargs):
            output.write_bytes(encode({"bomFormat": "CycloneDX", "specVersion": "1.6"}))

        def write_notices(output, *_):
            output.write_bytes(b"third-party fixture notices\n")

        release = candidate.assets.release_candidate
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(release, "ROOT", self.repo),
            patch.object(release.sbom_release, "build_inputs", return_value=([], ("cli", compiled), {})),
            patch.object(release.sbom_release, "write_sbom", side_effect=write_sbom),
            patch.object(preview_release_notices, "write_notices", side_effect=write_notices),
        ):
            candidate.assets.write_preview_receipts(
                self.input, build, record(archive), build / "verified-exacopy",
                observed, manifest, {}, floors, plan,
            )

    def import_candidate(self, request):
        return candidate.import_candidate(request, self.evidence, self.binary, request.route, SOURCE)

    def assert_refuses_before_stage(self, request, reason):
        with self.assertRaisesRegex(candidate.Blocked, reason):
            self.import_candidate(request)
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.evidence.exists())

    def test_direct_import_preserves_producer_identity_and_exact_bytes(self):
        request = self.request()
        frozen = self.import_candidate(request)
        self.assertEqual(frozen.binary.read_bytes(), self.elf)
        self.assertEqual(frozen.manifest, self.evidence / "result.json")
        self.assertEqual(frozen.report["campaign_route"], DIRECT)
        self.assertEqual(frozen.report["producer_route"], EMBEDDED)
        self.assertEqual(frozen.report["transport"], request.transport())
        self.assertEqual(frozen.report["compiled_features"], list(candidate.FEATURES))
        self.assertEqual(frozen.report["archive"], record(self.input / candidate.ARCHIVE))
        self.assertEqual(frozen.report["archive_observation"]["inode"], (self.input / candidate.ARCHIVE).stat().st_ino)
        self.assertEqual(frozen.report["binary"], record(self.binary))
        self.assertEqual(frozen.report["staged_executable"]["mode"], 0o500)
        self.assertEqual(frozen.report["schema"], candidate.CANDIDATE_SCHEMA)
        frozen.verify_archive()
        with self.assertRaisesRegex(candidate.Blocked, "route"):
            candidate.verify_staged_candidate(frozen.manifest, frozen.binary, frozen.digest, EMBEDDED, SOURCE)

    def test_wireguard_child_rejects_wrong_parent_digest_and_custody(self):
        self.elf = elf_bytes(osabi=3)
        frozen = self.import_candidate(self.request(route=EMBEDDED))
        self.assertEqual(
            candidate.verify_staged_candidate(frozen.manifest, frozen.binary, frozen.digest, EMBEDDED, SOURCE),
            frozen.report,
        )
        with self.assertRaisesRegex(candidate.Blocked, "parent-known digest"):
            candidate.verify_staged_candidate(frozen.manifest, frozen.binary, "f" * 64, EMBEDDED, SOURCE)
        replacement = self.stage / "replacement"
        replacement.write_bytes(self.elf)
        replacement.chmod(0o500)
        replacement.replace(self.binary)
        with self.assertRaisesRegex(candidate.Blocked, "custody changed"):
            frozen.verify()

    def test_input_mutation_invalidates_frozen_candidate(self):
        frozen = self.import_candidate(self.request())
        license_path = self.input / candidate.LICENSE
        moved = self.root / "moved-license"
        license_path.rename(moved)
        license_path.write_bytes(moved.read_bytes())
        with self.assertRaisesRegex(candidate.Blocked, "input or staged custody changed"):
            frozen.verify()

    def test_candidate_may_not_replace_an_incumbent(self):
        request = self.request()
        self.binary.write_bytes(b"incumbent")
        with self.assertRaises(FileExistsError):
            self.import_candidate(request)
        self.assertEqual(self.binary.read_bytes(), b"incumbent")

    def test_source_tree_and_run_binding_are_independent_of_valid_receipt_hash(self):
        def swap(receipt):
            receipt["workflow"]["run_attempt"] = "2"

        self.assert_refuses_before_stage(self.request(receipt_change=swap), "producer provenance")

    def test_wrong_source_tree_refuses_even_with_a_valid_producer_receipt_hash(self):
        def swap(receipt):
            receipt["source"] = SOURCE | {"git_tree": "0" * 40}

        self.assert_refuses_before_stage(self.request(receipt_change=swap), "producer provenance")

    def test_refuses_inexact_intent_even_with_matching_intent_digest(self):
        self.intent_path.write_bytes(encode(self.intent | {"tag_alias": "v0.1.0-preview.2"}))
        self.assert_refuses_before_stage(self.request(), "committed exact preview request")

    def test_candidate_notices_and_sbom_are_hash_bound(self):
        request = self.request()
        (self.input / candidate.NOTICES).write_bytes(b"substituted notices")
        self.assert_refuses_before_stage(request, "legal assets differ")

    def test_provenance_must_attest_exact_toolchain_and_build_command(self):
        def swap(receipt):
            receipt["cargo_args"].remove("--locked")

        self.assert_refuses_before_stage(self.request(receipt_change=swap), "producer provenance")

    def test_checksum_inventory_is_closed(self):
        request = self.request()
        with (self.input / candidate.CHECKSUMS).open("ab") as checksums:
            checksums.write(b"unrelated member\n")
        self.assert_refuses_before_stage(request, "checksum inventory")

    def test_input_inventory_refuses_an_unexpected_member(self):
        request = self.request()
        (self.input / "unrelated").write_bytes(b"other")
        self.assert_refuses_before_stage(request, "unexpected member")

    def test_input_member_refuses_same_bytes_symlink(self):
        request = self.request()
        original = self.input / candidate.ARCHIVE
        moved = self.root / "moved"
        original.rename(moved)
        original.symlink_to(moved)
        self.assert_refuses_before_stage(request, "allowed identity")

    def test_download_directory_requires_private_permissions(self):
        request = self.request()
        self.input.chmod(0o755)
        self.assert_refuses_before_stage(request, "outside its owner scope")

    def test_elf_header_must_match_routed_target(self):
        self.elf = elf_bytes(machine=183)
        self.assert_refuses_before_stage(self.request(), "Linux x86-64")

    def test_elf_header_refuses_foreign_osabi(self):
        self.elf = elf_bytes(osabi=9)
        self.assert_refuses_before_stage(self.request(), "Linux x86-64")

    def test_receipt_binds_parsed_archive_and_exact_elf(self):
        def swap(receipt):
            receipt["binary"]["sha256"] = "f" * 64

        self.assert_refuses_before_stage(self.request(receipt_change=swap), "archive or ELF differs")

    def test_normal_and_candidate_only_empty_inputs_are_distinct(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT))
        with patch.dict(os.environ, {"GITHUB_JOB": "preview-direct"}, clear=True), self.assertRaisesRegex(
            candidate.Blocked, "no admitted candidate mode",
        ):
            candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)
        environment = {"GITHUB_JOB": "embedded", "GITHUB_WORKFLOW_REF": candidate.WORKFLOW_REF}
        with patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
            candidate.Blocked, "no admitted candidate mode",
        ):
            candidate.CandidateRequest.from_hosted_environment(self.root, route=EMBEDDED)

    def test_partial_or_extra_candidate_environment_cannot_fall_back(self):
        environment = {candidate.ENV_PREFIX + "ARTIFACT_ID": "123"}
        with patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
            candidate.Blocked, "complete exact artifact binding",
        ):
            candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)

    def hosted_environment(self, route, **values):
        return {
            "GITHUB_JOB": candidate.JOBS[route],
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "replicraft/ExaCopy",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", "GITHUB_WORKFLOW_REF": candidate.WORKFLOW_REF,
            "GITHUB_SHA": SOURCE["revision"], "GITHUB_WORKFLOW_SHA": SOURCE["revision"],
            "GITHUB_RUN_ID": "73", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": str(self.root),
        } | {candidate.ENV_PREFIX + key: value for key, value in values.items()}

    def test_reserved_hosted_mode_requires_exact_controller_route_and_complete_values(self):
        environment = self.hosted_environment(
            DIRECT, MODE="requested", ARTIFACT_ID="123", ARTIFACT_DIGEST="a" * 64, RECEIPT_SHA256="b" * 64,
            ARCHIVE_SHA256="c" * 64, REQUEST_SHA256="d" * 64,
        )
        with (
            patch.object(candidate.sys, "platform", "linux"),
            patch.object(candidate, "require_directory"),
            patch.object(os, "getuid", return_value=501),
            patch.object(os, "geteuid", return_value=501),
        ):
            with patch.dict(os.environ, environment, clear=True):
                request = candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)
                self.assertEqual(request.root, self.input)
                self.assertEqual(request.route, DIRECT)
                self.assertEqual(request.artifact_id, "123")
            with patch.dict(os.environ, environment | {"GITHUB_WORKFLOW_SHA": "f" * 40}, clear=True):
                with self.assertRaisesRegex(candidate.Blocked, "exact hosted main push job"):
                    candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)
            with patch.dict(os.environ, environment | {candidate.ENV_PREFIX + "ARTIFACT_ID": ""}, clear=True):
                with self.assertRaisesRegex(candidate.Blocked, "artifact identity is malformed"):
                    candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)
            with patch.dict(os.environ, environment | {"GITHUB_RUN_ATTEMPT": "2"}, clear=True):
                with self.assertRaisesRegex(candidate.Blocked, "first hosted run attempt"):
                    candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)

    def test_ordinary_provider_b_is_explicit_even_with_a_persisted_request(self):
        environment = self.hosted_environment(EMBEDDED, MODE="not-requested") | {"GITHUB_RUN_ATTEMPT": "2"}
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(candidate.sys, "platform", "linux"),
            patch.object(candidate, "require_directory"),
            patch.object(os, "getuid", return_value=501),
            patch.object(os, "geteuid", return_value=501),
        ):
            self.assertIsNone(candidate.CandidateRequest.from_hosted_environment(self.root, route=EMBEDDED))
            with self.assertRaisesRegex(candidate.Blocked, "ordinary provider-B"):
                candidate.CandidateRequest.from_hosted_environment(self.root, route=DIRECT)


if __name__ == "__main__":
    unittest.main()

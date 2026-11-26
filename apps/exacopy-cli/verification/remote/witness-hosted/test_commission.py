import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import commission
import fixture_authority
from native_supervision import CleanupUnconfirmed, ProcessResult


class HostedWrapper(unittest.TestCase):
    build = "1" * 64
    request_blake3 = "7" * 64
    job_id = "01234567-1234-1234-1234-0123456789ab"
    stage = "capture-12345678-1234-1234-1234-0123456789ab"
    revision = "a" * 40
    current = {"revision": revision, "git_tree": "b" * 40, "lock_sha256": "c" * 64}
    pins = dict.fromkeys(commission.PIN_INPUTS, "d" * 64)
    sources = ({"fixture": "e" * 64}, "f" * 64)
    header = {"source_blake3": build, "prior_head_blake3": build}

    def positive(self, **changes):
        proof = {
            "schema_version": 1, "outcome": "passed", "phase": "witness_closeout",
            "route": commission.ROUTES[0], "authority_scope": "fixture_only", "request_blake3": self.request_blake3,
            **dict.fromkeys(commission.DIGESTS, self.build),
            "terminal_head_blake3": "2" * 64, **commission.PASS_FIELDS,
        }
        return commission.MARKER + json.dumps(proof | changes).encode() + b"\n"

    def test_absent_request_blocks_before_staging_or_spawn(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(commission, "logged_command") as spawn:
            with self.assertRaisesRegex(commission.Blocked, "missing-external-fixture-input"):
                commission.run_selected(Path("/unused"), {}, commission.ROUTES[0], "positive")
            spawn.assert_not_called()

    def test_exact_positive_requires_each_independent_binding(self):
        valid = self.positive(extra="private-looking text")
        projection = commission.fixture_result(valid, commission.ROUTES[0], self.build, self.header, self.build, self.request_blake3)
        self.assertNotIn("extra", projection)
        for settings in (
            {"operation": True}, {"same_inode_links": 1}, {"public_target_absent": False},
            {"build_blake3": "3" * 64}, {"journal_terminal_kind": 4},
            {"terminal_head_blake3": self.build}, {"route": commission.ROUTES[1]},
            {"authority_scope": "production"}, {"source_blake3": "3" * 64},
            {"prior_head_blake3": "4" * 64}, {"qualification_blake3": "5" * 64},
            {"request_blake3": "8" * 64},
        ):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                commission.fixture_result(self.positive(**settings), commission.ROUTES[0], self.build, self.header, self.build, self.request_blake3)
        with self.assertRaises(ValueError):
            commission.fixture_result(valid + valid, commission.ROUTES[0], self.build, self.header, self.build, self.request_blake3)


    def test_libtest_requires_result_on_an_independent_line(self):
        prefix = f"running 1 test\ntest {commission.SELECTOR} ... ".encode()
        verified = (commission.ROUTES[0], self.build, self.header, self.build, self.request_blake3)
        with self.assertRaises(ValueError):
            commission.fixture_result(prefix + self.positive(), *verified)
        self.assertEqual(commission.fixture_result(prefix + b"\n" + self.positive() + b"ok\n", *verified)["outcome"], "passed")

    def build_manifest(self, selected):
        info = selected.stat()
        copied = {
            "path": str(selected), "size": info.st_size, "sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "link_count": info.st_nlink,
            "mode": 0o500, "modified_ns": info.st_mtime_ns, "changed_ns": info.st_ctime_ns,
        }
        details = {"status": "exited", "exit_status": 0, "log_sha256": "5" * 64}
        return {
            "schema": commission.BUILD_SCHEMA, "status": "built", "selector": commission.SELECTOR,
            "route": "direct-pinned-tcp-v1", "source_before": self.current, "source_after": self.current,
            "argv": commission.expected_build_command("experimental-ssh-capture"), "pin_inputs_sha256": self.pins,
            "pin_logs_sha256": dict.fromkeys((
                "pin-pre.apfs.log", "pin-pre.transport.log", "pin-post.apfs.log", "pin-post.transport.log",
            ), "4" * 64),
            "compiled_features": ["experimental-ssh-capture"], "toolchain": details, "process": details,
            "build_log_sha256": "5" * 64, "selector_log_sha256": "6" * 64,
            "build_size": copied["size"], "build_sha256": copied["sha256"],
            "build_blake3_derive_key": self.build,
            "compiler_reported_executable": copied | {"inode": copied["inode"] + 1},
            "checked_executable_copy": copied,
        }

    def invoke(self, transcript, case="positive", process=ProcessResult("exited", 0), *,
               manifest_changes=None, change_request=False, wrong_manifest_digest=False,
               qualification=None, mutate_refusal=None):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            work = root / "private"
            work.mkdir()
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            job = destination / (".exacopy-" + self.job_id)
            job.mkdir(mode=0o700)
            for name in ("stage", "journal", "receipts"):
                (job / name).mkdir(mode=0o700)
            for path in ("owner.cbor", "stage/" + self.stage, "journal/" + commission.FIRST_SEGMENT):
                (job / path).write_text(path)
                (job / path).chmod(0o600)
            request = root / "request"
            request.write_text(json.dumps({
                "schema_version": 1, "route": commission.ROUTES[0], "op2": {"record": "/external/op2"},
                "strategy": "verified_prefix", "allow_witness_retention": True, **self.header,
                "destination_root": str(destination), "job_id": self.job_id, "target": "absent", "stage": self.stage,
            }))
            request.chmod(0o600)
            binary = root / "supplied"
            binary.write_bytes(b"\x7fELF fixture executable placeholder")
            binary.chmod(0o500)
            original_request = request.read_bytes()
            manifest = root / "build-result"
            data = self.build_manifest(binary) | (manifest_changes or {})
            manifest.write_text(json.dumps(data))
            manifest.chmod(0o600)
            env = {
                "EXACOPY_HOSTED_WITNESS_BUILD_MANIFEST": str(manifest),
                "EXACOPY_HOSTED_WITNESS_BUILD_MANIFEST_SHA256":
                    ("0" * 64 if wrong_manifest_digest else hashlib.sha256(manifest.read_bytes()).hexdigest()),
                "EXACOPY_HOSTED_WITNESS_SOURCE_SET_SHA256": self.sources[1],
                commission.QUALIFICATION: self.build if qualification is None else qualification,
                "EXACOPY_HOSTED_WITNESS_REFUSAL_DESTINATION": str(destination),
                commission.REQUEST: str(request), "EXACOPY_HOSTED_WITNESS_BINARY": str(binary),
                "EXACOPY_HOSTED_WITNESS_BINARY_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "EXACOPY_HOSTED_WITNESS_BUILD_BLAKE3": self.build,
                "EXACOPY_HOSTED_WITNESS_REVISION": self.revision, "GITHUB_SHA": self.revision,
                "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted",
                "GITHUB_REPOSITORY": "replicraft/ExaCopy", "GITHUB_REF": "refs/heads/main",
                "GITHUB_REF_PROTECTED": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            }

            def spawn(command, output, timeout, **options):
                self.assertTrue((root / "cleanup-unconfirmed.json").is_file())
                self.assertEqual(command[1:], [
                    commission.SELECTOR, "--exact", "--ignored", "--nocapture", "--test-threads=1",
                ])
                self.assertEqual(options["env"]["EXACOPY_HOSTED_WITNESS_ROUTE"], commission.ROUTES[0])
                self.assertEqual(options["env"]["EXACOPY_HOSTED_WITNESS_CASE"], case)
                self.assertEqual(options["output_limit"], commission.MAX_TRANSCRIPT)
                self.assertEqual(timeout, 180)
                if change_request:
                    request.rename(root / "previous-request")
                    request.write_bytes(b"replacement")
                private = Path(options["env"][commission.REQUEST])
                self.assertEqual(private, work / "request.json")
                self.assertEqual(private.read_bytes(), original_request)
                self.assertEqual(options["env"][commission.REQUEST_DIGEST], self.request_blake3)
                self.assertEqual(options["env"][commission.QUALIFICATION], self.build)
                if callable(mutate_refusal):
                    mutate_refusal(job)
                elif mutate_refusal is not None:
                    (job / mutate_refusal).write_text("unexpected fixture change")
                if isinstance(process, Exception):
                    raise process
                output.write_bytes(transcript)
                return process

            with (
                patch.dict(os.environ, env, clear=True),
                patch.object(commission.sys, "platform", "linux"),
                patch.object(commission, "observe_source", return_value=(self.current, self.pins)),
                patch.object(commission, "observe_witness_sources", return_value=self.sources),
                patch.object(commission, "stage_digest_tool", return_value=work / "b3sum"),
                patch.object(commission, "hash_request", return_value=self.request_blake3),
                patch.object(commission, "logged_command", side_effect=spawn) as called,
            ):
                output = {}
                if manifest_changes or wrong_manifest_digest or qualification == "":
                    with self.assertRaises(commission.Blocked):
                        commission.run_selected(work, output, commission.ROUTES[0], case)
                    called.assert_not_called()
                    return None, output
                if isinstance(process, Exception):
                    with self.assertRaises(CleanupUnconfirmed):
                        commission.run_selected(work, output, commission.ROUTES[0], case)
                    self.assertTrue((root / "cleanup-unconfirmed.json").is_file())
                    return None, output
                if mutate_refusal is not None:
                    with self.assertRaises(ValueError):
                        commission.run_selected(work, output, commission.ROUTES[0], case)
                    self.assertNotIn("refusal_preservation", output)
                    return None, output
                status = commission.run_selected(work, output, commission.ROUTES[0], case)
            self.assertFalse((root / "cleanup-unconfirmed.json").exists())
            return status, output

    def test_positive_keeps_only_bounded_projected_report(self):
        status, report = self.invoke(self.positive())
        self.assertEqual(status, 0)
        self.assertEqual(report["fixture"]["journal_terminal_kind"], 41)

    def refusal(self, reason="op2_qualification_refused", **changes):
        row = {
            "schema_version": 1, "outcome": "blocked", "phase": "preflight", "reason": reason,
            "qualification_blake3": self.build, "request_blake3": self.request_blake3,
        }
        return commission.MARKER + json.dumps(row | changes).encode() + b"\n"

    def test_refusal_requires_exact_operation_two_and_unchanged_namespace(self):
        status, report = self.invoke(self.refusal(), "qualification-refusal")
        self.assertEqual(status, 0)
        self.assertEqual(report["refusal_preservation"]["status"], "unchanged")
        self.assertEqual(self.invoke(self.refusal("qualification_refused"), "qualification-refusal")[0], 77)
        self.assertEqual(self.invoke(self.refusal("missing_authority"), "qualification-refusal")[0], 77)
        self.assertEqual(self.invoke(self.positive(), "qualification-refusal")[0], 1)
        self.invoke(self.refusal(), "qualification-refusal", qualification="")
        for field in ("qualification_blake3", "request_blake3"):
            self.assertRaises(ValueError, self.invoke, self.refusal(**{field: "9" * 64}), "qualification-refusal")
        for changed in ("stage/" + self.stage, "journal/" + commission.FIRST_SEGMENT, "receipts/receipt.cbor", "witness.unexpected"):
            with self.subTest(changed=changed):
                self.invoke(self.refusal(), "qualification-refusal", mutate_refusal=changed)

    def test_refusal_growth_rechecks_limit_before_a_second_read(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "owner"
            path.write_bytes(b"seed")
            with path.open("rb") as stream:
                original = commission.observation(os.fstat(stream.fileno()))
                observed, _ = commission.observe_refusal_file(path, stream, 8, original, ValueError)
                self.assertEqual(observed, original)
                with path.open("ab") as writer:
                    writer.write(b"-beyond-limit")
                with patch.object(stream, "read", side_effect=AssertionError("must refuse before reading")):
                    with self.assertRaisesRegex(ValueError, "file-size-outside-bound"):
                        commission.observe_refusal_file(path, stream, 8, original, ValueError)

        def grow_owner(job):
            with (job / "owner.cbor").open("r+b") as writer:
                writer.truncate(16 * 1024 + 1)

        status, report = self.invoke(self.refusal(), "qualification-refusal", mutate_refusal=grow_owner)
        self.assertIsNone(status)
        self.assertNotIn("refusal_preservation", report)

    def test_build_manifest_wrong_tree_lock_pins_or_unapproved_bytes_refuse_spawn(self):
        for change in (
            {"source_after": self.current | {"git_tree": "0" * 40}},
            {"source_before": self.current | {"lock_sha256": "0" * 64}},
            {"pin_inputs_sha256": {}}, {"selector": "other"}, {"checked_executable_copy": {}},
        ):
            with self.subTest(change=change):
                self.invoke(self.positive(), manifest_changes=change)
        self.invoke(self.positive(), wrong_manifest_digest=True)

    def test_original_request_rebinding_cannot_reach_fixture(self):
        status, report = self.invoke(self.positive(), change_request=True)
        self.assertEqual(status, 0)
        self.assertEqual(len(report["staged_request"]["sha256"]), 64)
        self.assertGreater(report["staged_request"]["inode"], 0)

    def test_known_failure_and_unconfirmed_drain_stay_distinct(self):
        self.assertEqual(self.invoke(b"", process=ProcessResult("exited", 101))[0], 1)
        self.assertIsNone(self.invoke(b"", process=CleanupUnconfirmed())[0])

    def test_operation_two_projection_uses_exact_canonical_mask(self):
        vector = fixture_authority.independent_encoder()
        facts = {
            "device": "1", "inode": "2", "effective_uid": 3, "effective_gid": 4,
            "boot_id_hex": "01" * 16, "mount_namespace": "5", "mount_id": "6",
            "unique_mount": "7", "architecture": "x86_64",
            "kernel_release_hex": "aa", "kernel_build_hex": "bb", "mount_record_hex": "cc",
        }
        actual = fixture_authority.observed_payload(vector, facts, self.build, b"a" * 16, b"b" * 32, b"c" * 32)
        self.assertTrue(actual.endswith(bytes.fromhex("06020702081a00ffffff")))


if __name__ == "__main__":
    unittest.main()

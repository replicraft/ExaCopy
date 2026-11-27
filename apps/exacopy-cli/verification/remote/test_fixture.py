"""Harness controls without a native destination or a network peer."""

from contextlib import ExitStack, contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import campaign
from campaign import HeldInputs, absent, command_for, namespace, receipt_absent
from fixture import Blocked, Failed, PeerLog, checked_read, compare_files, digest_executable, hash_source, opened
from qualification_request import (
    PARENT_FIELDS, SUBSTRATE_CASES, checked_native, digest, exact_build, strict_json, substrate_closure,
)


class FixtureControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def private(self, name, data):
        output = self.root / name
        output.write_bytes(data)
        output.chmod(0o600)
        return output

    def test_observed_peer_endpoint_and_authentication_are_required(self):
        listener = ipaddress.ip_address("10.23.0.1")
        local = ipaddress.ip_address("10.23.0.2")
        log = self.private("sshd", b"a discarded earlier fixture line\n")
        peer = PeerLog(log, "reader", listener, 2243, local)
        with log.open("ab") as file:
            file.write(
                b'Connection from 10.23.0.2 port 42119 on 10.23.0.1 port 2243 rdomain ""\n'
                b'Accepted publickey for reader from 10.23.0.2 port 42119 ssh2: ED25519 SHA256:fixture\n'
            )
        peer.check(1, self.root / "positive.log")
        peer.check(0, self.root / "no-redial.log")
        with log.open("ab") as file:
            file.write(
                b'Connection from 127.0.0.1 port 42119 on 10.23.0.1 port 2243 rdomain ""\n'
                b'Accepted password for reader from 127.0.0.1 port 42119 ssh2\n'
            )
        with self.assertRaisesRegex(Failed, "different route peer"):
            peer.check(1, self.root / "substitute.log")

    def test_expected_absence_does_not_ignore_even_an_unauthenticated_dial(self):
        listener = ipaddress.ip_address("127.0.0.1")
        log = self.private("sshd", b"")
        peer = PeerLog(log, "reader", listener, 2243, None)
        with log.open("ab") as file:
            file.write(b'Connection from 127.0.0.1 port 42119 on 127.0.0.1 port 2243\n')
        with self.assertRaisesRegex(Failed, "unexpected number"):
            peer.check(0, self.root / "unexpected.log")

    def test_readback_refuses_mismatched_bytes_and_record_hard_link(self):
        source = self.private("source", b"abc")
        target = self.private("target", b"abc")
        compare_files(source, target, source.stat())
        target.write_bytes(b"abd")
        with self.assertRaisesRegex(Failed, "independent bytes differed"):
            compare_files(source, target, source.stat())
        os.link(target, self.root / "alias")
        with self.assertRaisesRegex(Blocked, "not a single regular file"):
            checked_read(target, 3)


    def test_executable_digests_use_the_entire_held_descriptor_after_header_check(self):
        contents = b"\x7fELF" + bytes(range(256)) * 4096
        binary = self.private("executable", contents)
        child = self.private("digest-child", (
            b"#!/usr/bin/env python3\n"
            b"import hashlib, sys\n"
            b"print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n"
        ))
        child.chmod(0o700)
        expected = hashlib.sha256(contents).hexdigest()
        with ExitStack() as scope:
            inputs = HeldInputs(scope)
            raw = inputs.open(binary, len(contents), buffering=0)
            self.assertEqual(raw.read(4), b"\x7fELF")
            self.assertEqual(digest_executable(raw, child), (expected, expected))
            inputs.recheck()
        self.assertEqual(hash_source(binary, child, len(contents), len(contents))[1], expected)
        buffered, _ = opened(binary, len(contents))
        with buffered:
            self.assertEqual(buffered.read(4), b"\x7fELF")
            with self.assertRaisesRegex(Failed, "unbuffered held descriptor"):
                digest_executable(buffered, child)

    def test_campaign_argv_matches_the_public_parser_vectors(self):
        fixture = Path(__file__).with_name("campaign-argv.json")
        vectors = json.loads(fixture.read_text(encoding="utf-8"))
        args = SimpleNamespace(binary=Path("/fixture/exacopy"), **{
            name: Path(value) for name, value in vectors["options"].items()
        })
        for case in vectors["cases"]:
            with self.subTest(subcommand=case["subcommand"]):
                override = case["qualification_override"]
                command = command_for(
                    args, case["subcommand"], case["operands"],
                    Path(override) if override is not None else None,
                )
                self.assertEqual(command[0], args.binary)
                self.assertEqual(list(map(os.fspath, command[1:])), case["argv"])

    def test_campaign_retains_only_allowlisted_exit_mismatch_fields(self):
        path = self.root / "campaign"
        arguments = ["campaign", "--route", campaign.ROUTES[1]]
        for name in (
            "binary", "destination", "owner-profile", "ssh-profile", "qualification",
            "trust", "source-small", "source-interrupt", "sshd-log", "evidence",
        ):
            arguments.extend((f"--{name}", str(path if name == "evidence" else self.root / name)))
        report = {
            "schema": "exacopy.cli.remote_download", "schema_version": "1.0", "publication": "not_published",
            "error": {"code": "E_INVALID_REQUEST", "message": "private input", "job_directory": "/private/path"},
        }
        raw = json.dumps(report).encode()

        @contextmanager
        def child(_evidence, _name, _argv, _cwd, stdout, _stderr):
            stdout.write(raw)
            yield SimpleNamespace(returncode=2, wait_for_exit=lambda _timeout: None)

        def cases(args, _summary):
            args.inputs = SimpleNamespace(recheck=lambda: None)
            campaign.run_case(args, "qualification-path-control", ("get",), ("source", "target"), 3)

        with (
            patch.object(campaign.sys, "argv", arguments),
            patch.object(campaign, "cases", side_effect=cases),
            patch.object(campaign, "owned_cli_process", side_effect=child),
        ):
            self.assertEqual(campaign.main(), 1)
        summary = json.loads((path / "summary.json").read_bytes())
        self.assertEqual(summary["failed_case"], {
            "case": "qualification-path-control", "exit_status": 2, "expected_exit_status": 3,
            "publication": "not_published", "error_code": "E_INVALID_REQUEST",
        })
        self.assertEqual(summary["artifacts_sha256"]["qualification-path-control.stdout"],
                         hashlib.sha256(raw).hexdigest())
        invalid = campaign.CaseExitMismatch("get", 4, 11, {"publication": [], "error": {"code": "private"}})
        self.assertEqual(invalid.observation, {"case": "get", "exit_status": 4, "expected_exit_status": 11})
        self.assertNotIn("private input", json.dumps(summary))

    def test_unsigned_facts_expect_exact_bounded_value_shapes(self):
        observation = {
            "device": "2", "inode": "23", "mount_namespace": "4", "mount_id": "5",
            "unique_mount": "6", "effective_uid": 7, "effective_gid": 8,
            "architecture": "aarch64", "boot_id_hex": "05" * 16,
            "kernel_release_hex": "6162", "kernel_build_hex": "6364", "mount_record_hex": "6566",
        }
        self.assertTrue(checked_native(observation))
        self.assertFalse(checked_native(dict(observation, effective_uid=True)))
        self.assertFalse(checked_native(dict(observation, unique_mount=str(2**64))))
        self.assertFalse(checked_native(dict(observation, mount_record_hex="00" * 2049)))


    def test_held_input_recheck_detects_same_size_mutation(self):
        profile = self.private("profile", b"before")
        with ExitStack() as scope:
            inputs = HeldInputs(scope)
            self.assertEqual(inputs.read(profile, 20), b"before")
            inputs.recheck()
            profile.write_bytes(b"after!")
            with self.assertRaisesRegex(Failed, "changed"):
                inputs.recheck()

    def test_nofollow_namespace_refuses_dangling_receipt_directory_and_stray_entries(self):
        self.assertTrue(receipt_absent(self.root))
        alias = self.root / "receipts"
        alias.symlink_to(self.root / "no-receipt-directory")
        self.assertFalse(absent(alias))
        with self.assertRaisesRegex(Failed, "private receipt directory"):
            receipt_absent(self.root)
        with self.assertRaisesRegex(Failed, "unexpected destination name"):
            namespace(self.root, set(), pending_job=True)

    def test_unsigned_request_refuses_manual_attribution_and_ambiguous_claims(self):
        with self.assertRaisesRegex(Blocked, "wrapper-owned"):
            exact_build(None, {}, {"repository_attribution": "measured-selected-elf"}, {})
        with self.assertRaisesRegex(Failed, "duplicate field"):
            strict_json(b'{"status":"blocked","status":"built"}')

    def test_substrate_must_bind_both_clean_source_pins_and_the_observed_parent(self):
        source = {"revision": "a", "git_tree": "b", "lock_sha256": "c"}
        parent_fields = ("1", "2", "03" * 16, "4", "5", "6")
        parent = dict(zip(PARENT_FIELDS, parent_fields, strict=True))
        facts = {"destination": parent}
        cuts = "".join(f"EXACOPY_REMOTE_SUBSTRATE_PASS {cut}\n" for cut in SUBSTRATE_CASES)
        marker = "EXACOPY_REMOTE_SUBSTRATE_PARENT " + " ".join(parent_fields) + "\n"
        log = (cuts + marker).encode("ascii")
        manifest = {
            **source, "source_before": source, "source_after": source,
            "destination_parent": parent, "cases": list(SUBSTRATE_CASES), "process_exit": 0,
            "log_sha256": digest(log),
        }
        substrate_closure(manifest, facts, source, log)
        with self.assertRaisesRegex(Failed, "exact clean"):
            substrate_closure(dict(manifest, source_after=dict(source, git_tree="changed")), facts, source, log)
        with self.assertRaisesRegex(Blocked, "exact observed native parent"):
            substrate_closure(dict(manifest, destination_parent=dict(parent, inode="12")), facts, source, log)

        # The imported manifest exactly agrees with the selected facts and hashes
        # the foreign or ambiguous transcript. Only the raw marker disqualifies it.
        for rejected in (
            cuts + marker.replace(" 1 2 ", " 1 12 "),
            cuts + marker + marker,
            cuts + marker + "EXACOPY_REMOTE_SUBSTRATE_PARENT malformed\n",
            cuts,
        ):
            with self.subTest(log=rejected):
                raw = rejected.encode("ascii")
                with self.assertRaisesRegex(Blocked, "exact observed native parent"):
                    substrate_closure(dict(manifest, log_sha256=digest(raw)), facts, source, raw)


if __name__ == "__main__":
    unittest.main()

"""Portable isolation controls for the hosted READ timeout provider."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from remote_commissioning import EvidenceFailed, check_case_exports, export
from remote_commissioning_peer import NOLOGIN, SSHD
from remote_retry_commissioning import CAMPAIGN_FILES, COMMAND, RetryFixture


class RetryProviderTests(unittest.TestCase):
    def test_chroot_only_command_preserves_existing_peer_restrictions(self):
        fixture = RetryFixture("0a" * 10, 65534)
        config = fixture.sshd_config(43521)
        for row in (
            "ListenAddress 127.0.0.1:43521",
            f"AllowUsers {fixture.account}@127.0.0.1",
            f"ChrootDirectory {fixture.chroot}",
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "DisableForwarding yes",
            "PermitTTY no",
            "MaxSessions 1",
            f"Subsystem sftp {NOLOGIN}",
            f"ForceCommand {COMMAND}",
        ):
            self.assertIn(row + "\n", config)
        self.assertEqual(fixture.jail_shell, fixture.chroot / Path(NOLOGIN).relative_to("/"))
        self.assertTrue(fixture.retry_trace.is_relative_to(fixture.chroot))
        self.assertTrue(fixture.retry_release.is_relative_to(fixture.chroot))
        self.assertTrue(Path(SSHD).is_absolute())
        self.assertEqual(config.count("ForceCommand "), 1)

    def test_positive_export_requires_every_transcript_and_matches_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            work, report = root / "work", root / "report"
            (work / "campaign").mkdir(parents=True)
            payload = b"independent fixture transcript\n"
            digest = hashlib.sha256(payload).hexdigest()
            declaration = {"artifacts_sha256": {Path(path).name: digest for path in CAMPAIGN_FILES}}
            (work / "campaign/summary.json").write_text(json.dumps(declaration))
            for path in CAMPAIGN_FILES:
                (work / path).write_bytes(payload)
            hashes = export(work, report, CAMPAIGN_FILES)
            check_case_exports(report, hashes, CAMPAIGN_FILES)
            missing = next(iter(CAMPAIGN_FILES))
            with self.assertRaises(EvidenceFailed):
                check_case_exports(report, {key: val for key, val in hashes.items() if key != missing},
                                   CAMPAIGN_FILES)
            with self.assertRaises(EvidenceFailed):
                check_case_exports(report, hashes | {missing: "0" * 64}, CAMPAIGN_FILES)

    def test_failed_export_retains_terminal_without_private_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            work, report = root / "work", root / "report"
            (work / "campaign").mkdir(parents=True)
            terminal = "campaign/budget.terminal.json"
            (work / terminal).write_bytes(b'{"exit_status": 9, "elapsed_seconds": 41.5}\n')
            (work / "campaign/budget.stdout").write_bytes(b"private fixture paths")
            hashes = export(work, report, CAMPAIGN_FILES)
            self.assertEqual(hashes, {terminal: hashlib.sha256((work / terminal).read_bytes()).hexdigest()})
            self.assertFalse((report / "campaign/budget.stdout").exists())

    def test_only_exact_readonly_source_binding_and_public_trace(self):
        fixture = RetryFixture("0a" * 10, 65534)
        properties = fixture.sshd_properties()
        self.assertIn(f"{fixture.source}:{fixture.chroot / 'retry-input'}:norbind",
                      properties["BindReadOnlyPaths"].split())
        self.assertEqual(properties["KillMode"], "control-group")
        self.assertEqual(properties["ProtectControlGroups"], "yes")
        self.assertEqual(len(CAMPAIGN_FILES), 12)
        for path in CAMPAIGN_FILES:
            self.assertEqual(Path(path).parent, Path("campaign"))
            self.assertTrue(path.endswith((".openssh.log", ".terminal.json"))
                            or Path(path).name in ("sftp-events.log", "openssh.log"))


if __name__ == "__main__":
    unittest.main()

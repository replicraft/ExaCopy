"""Retained compatibility records must establish their claimed profile outcomes."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).with_name("reference")))
from check import check_compatibility


REPOSITORY = Path(__file__).resolve().parents[1]
COMPATIBILITY = REPOSITORY / "specs/compatibility"
LINUX_COPY = "evidence/linux-ext4-copy.json"
LINUX_DIFF = "evidence/linux-ext4-differential.json"
APFS_DIFF = "evidence/macos-apfs-differential.json"
REMOVE = object()


class CompatibilityEvidenceTests(unittest.TestCase):
    def test_accepts_retained_profiles(self):
        check_compatibility()

    def check_mutation(self, filename, keys, replacement, diagnostic):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "compatibility"
            shutil.copytree(COMPATIBILITY, directory)
            path = directory / filename
            report = json.loads(path.read_text())
            entry = report
            for key in keys[:-1]:
                entry = entry[key]
            if replacement is REMOVE:
                del entry[keys[-1]]
            else:
                entry[keys[-1]] = replacement
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(RuntimeError, diagnostic):
                check_compatibility(directory)

    def test_rejects_unknown_protocol_even_if_run_claims_pass(self):
        self.check_mutation(APFS_DIFF, ["protocol"], "exacopy-reference-v2", "ineligible evidence")

    def test_rejects_mismatched_host_or_reference_version(self):
        self.check_mutation(APFS_DIFF, ["configuration", "platform", "version"], "14.7.1",
                            "evidence platform disagrees")
        self.check_mutation(APFS_DIFF, ["configuration", "rsync_version"], "rsync  version 3.5.1  protocol version 33",
                            "reference version disagrees")

    def test_rejects_conflicting_independent_results(self):
        self.check_mutation(LINUX_DIFF, ["evidence", "cases", 3, "cmp_exit"], 0, "cmp result contradicts fixture")
        self.check_mutation(LINUX_DIFF, ["evidence", "cases", 3, "rsync_itemized_change"], "",
                            "rsync result contradicts fixture")

    def test_rejects_results_that_agree_on_a_diff_but_give_the_wrong_witness(self):
        self.check_mutation(LINUX_DIFF, ["evidence", "cases", 3, "exa_copy", "16", "report", "difference", "offset"],
                            "0", "wrong ExaCopy difference witness")

    def test_rejects_incomplete_worker_matrix_and_changed_symlink_outcome(self):
        self.check_mutation(APFS_DIFF, ["evidence", "cases", 0, "exa_copy"], {}, "missing worker report")
        self.check_mutation(APFS_DIFF, ["evidence", "symlink_control", "exa_copy", "complete"], True,
                            "missing final symlink refusal")

    def test_rejects_copy_without_verified_publication_and_preservation(self):
        self.check_mutation(LINUX_COPY, ["evidence", "workloads", 0, "assurance", "verification"], "none",
                            "invalid verified copy report")
        self.check_mutation(LINUX_COPY, ["evidence", "incumbent_control", "exacopy_error"], "E_OPEN_INPUT",
                            "missing incumbent-preservation evidence")

    def test_rejects_failed_attempt_relabelled_as_pass(self):
        self.check_mutation("evidence/linux-ext4-copy-enospc.json", ["outcome"], "passed",
                            "invalid retained failed reference attempt")
        self.check_mutation("evidence/macos-apfs-freefilesync-startup.json", ["outcome"], "passed",
                            "invalid retained startup probe")

    def test_rejects_unrelated_or_missing_evidence(self):
        self.check_mutation("inventory.v1.json", ["targets", 0, "profiles", 0, "evidence"], LINUX_DIFF,
                            "evidence platform disagrees")
        self.check_mutation("inventory.v1.json", ["targets", 0, "profiles", 0, "evidence"], "../missing.json",
                            "missing or out-of-scope evidence")

    def test_rejects_unclassified_failed_evidence(self):
        self.check_mutation("inventory.v1.json", ["targets", 1, "profiles", 2, "prior_attempt"], REMOVE,
                            "reference evidence has no classified profile")

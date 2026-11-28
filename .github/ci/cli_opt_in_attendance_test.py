"""Positive and negative controls for CLI nextest attendance gates."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from xml.etree import ElementTree

from cli_opt_in_attendance import (
    MAX_REPORT_BYTES,
    PUBLIC_STAGE_CASES,
    REMOTE_CASE,
    check_attendance,
)

OTHER_CASE = "assembly::linux::remote_journal::tests::unrelated_test"
REMOTE_EXPECTED = (
    "assembly::linux::remote_continued::tests::actual_signed_kind40_must_form_the_exact_clean_successor",
    (
        "assembly::linux::remote_continued::tests::hosted_witness::preflight::tests::"
        "original_capture_budget_and_native_projection_match_signed_next_pass"
    ),
    "assembly::ssh_session::tests::host_and_route_admission_precede_credential_offer_liveness",
    "assembly::ssh_session::tests::protected_key_worker_rechecks_the_same_offer_before_reading",
)

WITNESSED_EXPECTED = (
    (
        "assembly::linux::remote_journal::tests::capture::witnessed::"
        "held_native_donor_compares_a_live_positive_tail_and_refuses_a_changed_prefix"
    ),
    "assembly::linux::remote_journal::startup::witnessed::tests::witnessed_donor_extent_keeps_one_window_and_room_for_a_positive_tail",
    "assembly::linux::remote_witness_authority::tests::explicit_strategy_without_explicit_retention_is_never_consent",
    "assembly::linux::remote_witness_authority::tests::approval_is_bound_to_the_original_grant_instance_and_revokes_permanently",
    "assembly::linux::remote_continued::original::outcome::tests::source_refusal_is_kept_separate_from_retained_content_mismatch",
    "remote_report::tests::observed_incumbent_with_unconfirmed_record_preserves_conflict_evidence",
    "args::parser::remote::tests::witnessed_resume_requires_consent_and_both_independent_inputs",
    "remote_report::tests::witnessed_receipt_projection_reports_committed_evidence_and_retention",
    "assembly::linux::remote_continued::original::outcome::tests::confirmed_native_result_without_receipt_is_never_success",
    "assembly::linux::remote_continued::original::outcome::tests::observed_conflict_without_a_confirmed_record_requires_reconciliation",
    "assembly::linux::remote_continued::original::outcome::tests::confirmed_receipt_is_returned_only_for_the_actual_published_result",
    "assembly::linux::remote_continued::tests::actual_signed_kind40_must_form_the_exact_clean_successor",
    (
        "args::parser::remote_inspect_witness::tests::"
        "witness_inspection_accepts_only_explicit_read_only_inputs"
    ),
    (
        "remote_inspect_witness::report::tests::"
        "witness_inspection_projects_verified_commitment_and_redacts_refusals"
    ),
    (
        "remote_report::tests::"
        "published_with_omissions_uses_dedicated_nonclean_status_and_precise_evidence"
    ),
    "witness_archive::tests::valid_strict_report_preserves_independent_selection",
    "witness_archive::tests::duplicate_unknown_and_positional_fields_are_refused",
    "witness_archive::tests::incoherent_or_noncanonical_report_is_refused",
    "witness_archive::tests::complete_report_is_bounded_and_requires_one_document",
    "remote_report::tests::archive::producer_report_roundtrips_the_independently_selected_archive",
    "remote_report::tests::archive::inconsistent_archive_cannot_be_reported_as_committed_success",
)
APFS_EXPECTED = (
    "args::parser::recovery::apfs::tests::inspect_apfs_requires_independent_exact_selectors_and_keeps_raw_container_bytes",
    "apfs_inspect::report::tests::apfs_inspection_keeps_reconciliation_separate_from_history_and_receipt",
    "assembly::macos::job::tests::cli_inspection::apfs_inspect_dispatch_binds_the_independent_selection_and_preserves_the_job",
)
APFS_DEFAULT_EXPECTED = "args::parser::recovery::tests::inspect_apfs_is_hidden_without_the_exact_target_and_feature"
TRANSFER_CASE = "macos::tests::fixture_transfer_test"
RECREATE_EXPECTED = (
    "args::parser::sync_managed::tests::prepare_recreate_requires_explicit_direction_conflict_and_receipt",
    "sync_preview::managed_command::recreate::tests::prepare_recreate_refuses_oversize_receipt_without_candidate",
    (
        "assembly::linux::managed_sync::manual_recreate::tests::"
        "manual_recreate_selects_only_the_current_survivor_and_exact_conflict"
    ),
    (
        "assembly::linux::managed_sync::manual_recreate::tests::"
        "manual_recreate_refuses_nonabsence_and_the_absent_peers_read_ceiling"
    ),
)


class CliOptInAttendanceTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.report = Path(directory.name) / "junit.xml"

    def write_report(self, cases, siblings=()):
        statuses = {"skipped": "0", "failures": "0", "errors": "0"}
        suites = (("exacopy-cli", cases), *siblings)
        root = ElementTree.Element(
            "testsuites", name="nextest-run", tests=str(sum(len(names) for _, names in suites)), **statuses,
        )
        for suite_name, names in suites:
            suite = ElementTree.SubElement(root, "testsuite", name=suite_name, tests=str(len(names)), **statuses)
            for name in names:
                ElementTree.SubElement(
                    suite, "testcase", name=name, classname=suite_name,
                    timestamp="2026-11-27T12:00:00.000+00:00", time="0.001",
                )
        self.write_xml(root)
        return root

    def write_xml(self, root):
        ElementTree.ElementTree(root).write(self.report, encoding="utf-8", xml_declaration=True)

    def test_remote_requires_the_exact_owning_cases_and_allows_other_passing_cases(self):
        self.write_report([OTHER_CASE, *REMOTE_EXPECTED])
        self.assertEqual(check_attendance(self.report, "remote"), sorted(REMOTE_EXPECTED))

    def test_remote_refuses_each_missing_case_even_with_a_wrong_module_lookalike(self):
        for missing in REMOTE_EXPECTED:
            with self.subTest(missing=missing):
                present = [name for name in REMOTE_EXPECTED if name != missing]
                wrong_module = missing.replace("::tests::", "::other_tests::")
                self.write_report([*present, wrong_module])
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "remote")

    def test_witnessed_resume_requires_every_actual_owning_case(self):
        self.write_report([OTHER_CASE, *WITNESSED_EXPECTED])
        self.assertEqual(check_attendance(self.report, "witnessed-resume"), sorted(WITNESSED_EXPECTED))
        for missing in WITNESSED_EXPECTED:
            with self.subTest(missing=missing):
                present = [name for name in WITNESSED_EXPECTED if name != missing]
                self.write_report([*present, missing.replace("::tests::", "::unrelated::")])
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "witnessed-resume")
        self.write_report(WITNESSED_EXPECTED, (("exacopy-transfer", (TRANSFER_CASE,)),))
        with self.assertRaisesRegex(ValueError, "expected one nextest JUnit suite"):
            check_attendance(self.report, "witnessed-resume")

    def test_apfs_copy_requires_exact_cli_cases_alongside_other_suites(self):
        self.write_report(APFS_EXPECTED, (
            ("exacopy-cli::command", (OTHER_CASE,)), ("exacopy-transfer", (TRANSFER_CASE,)),
        ))
        self.assertEqual(check_attendance(self.report, "apfs-copy"), sorted(APFS_EXPECTED))
        for missing in APFS_EXPECTED:
            with self.subTest(missing=missing):
                present = [name for name in APFS_EXPECTED if name != missing]
                self.write_report([*present, missing.replace("::tests::", "::unrelated::")], (
                    ("exacopy-transfer", (TRANSFER_CASE, missing)),
                ))
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "apfs-copy")

    def test_apfs_copy_refuses_unsuccessful_or_missing_sibling_evidence(self):
        root = self.write_report(APFS_EXPECTED, (("exacopy-transfer", (TRANSFER_CASE,)),))
        ElementTree.SubElement(root[1][0], "failure")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "apfs-copy")
        for siblings in ((), (("exacopy-transfer", ()),)):
            with self.subTest(siblings=siblings):
                self.write_report(APFS_EXPECTED, siblings)
                with self.assertRaisesRegex(ValueError, "expected the exacopy-transfer unit-test suite"):
                    check_attendance(self.report, "apfs-copy")
        self.write_report(APFS_EXPECTED, (("exacopy-cli", (OTHER_CASE,)),))
        with self.assertRaisesRegex(ValueError, "expected unique named nextest JUnit suites"):
            check_attendance(self.report, "apfs-copy")

    def test_apfs_default_requires_the_owning_parser_case_in_workspace_evidence(self):
        self.write_report((APFS_DEFAULT_EXPECTED,), (("exacopy-model", (OTHER_CASE,)),))
        self.assertEqual(check_attendance(self.report, "apfs-default"), [APFS_DEFAULT_EXPECTED])
        self.write_report((OTHER_CASE,), (("exacopy-cli::command", (APFS_DEFAULT_EXPECTED,)),))
        with self.assertRaisesRegex(ValueError, f"required testcases missing: {APFS_DEFAULT_EXPECTED}$"):
            check_attendance(self.report, "apfs-default")

    def test_managed_sync_recreate_requires_each_completed_owning_case(self):
        self.write_report(RECREATE_EXPECTED)
        self.assertEqual(check_attendance(self.report, "managed-sync-recreate"), sorted(RECREATE_EXPECTED))
        for missing in RECREATE_EXPECTED:
            with self.subTest(missing=missing):
                present = [name for name in RECREATE_EXPECTED if name != missing]
                self.write_report([*present, missing.replace("::tests::", "::other_tests::")])
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "managed-sync-recreate")
        root = self.write_report(RECREATE_EXPECTED)
        ElementTree.SubElement(root[0][0], "skipped")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "managed-sync-recreate")

    def test_incomplete_session_record_cannot_satisfy_remote_attendance(self):
        root = self.write_report(REMOTE_EXPECTED)
        ElementTree.SubElement(root[0][1], "skipped")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "execution record"):
            check_attendance(self.report, "remote")

    def test_public_stage_requires_the_exact_inventory(self):
        expected = sorted(PUBLIC_STAGE_CASES)
        self.write_report(expected)
        self.assertEqual(check_attendance(self.report, "public-stage"), expected)
        self.write_report(expected[:-1])
        with self.assertRaisesRegex(ValueError, "required testcases missing"):
            check_attendance(self.report, "public-stage")
        self.write_report(expected + [OTHER_CASE])
        with self.assertRaisesRegex(ValueError, "unexpected public-stage testcases"):
            check_attendance(self.report, "public-stage")

    def test_zero_wrong_module_and_duplicate_remote_case(self):
        cases = [
            ([], "required testcases missing"),
            ([REMOTE_CASE.replace("remote_continued", "remote_download")], "required testcases missing"),
            ([REMOTE_CASE, REMOTE_CASE], "duplicate testcase"),
        ]
        for names, message in cases:
            with self.subTest(names=names):
                self.write_report(names)
                with self.assertRaisesRegex(ValueError, message):
                    check_attendance(self.report, "remote")

    def test_wrong_binary_suite_or_case(self):
        root = self.write_report([REMOTE_CASE])
        root[0].set("name", "exacopy-cli::integration")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "unit-test suite"):
            check_attendance(self.report, "remote")
        root[0].set("name", "exacopy-cli")
        root[0][0].set("classname", "exacopy-cli::integration")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "named exacopy-cli testcase"):
            check_attendance(self.report, "remote")

    def test_list_only_record_without_execution_fields(self):
        root = self.write_report([REMOTE_CASE])
        del root[0][0].attrib["timestamp"]
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "execution record"):
            check_attendance(self.report, "remote")

    def test_skipped_failed_errored_and_retried_case(self):
        for status in ("skipped", "failure", "error", "flakyFailure"):
            with self.subTest(status=status):
                root = self.write_report([REMOTE_CASE])
                ElementTree.SubElement(root[0][0], status)
                self.write_xml(root)
                with self.assertRaisesRegex(ValueError, "execution record"):
                    check_attendance(self.report, "remote")

    def test_inconsistent_or_unsuccessful_summary(self):
        for summary_index in (None, 0):
            for attribute, value, message in (
                ("tests", "2", "count does not match"),
                ("skipped", "1", "unsuccessful tests"),
                ("failures", "1", "unsuccessful tests"),
                ("errors", "1", "unsuccessful tests"),
            ):
                with self.subTest(summary_index=summary_index, attribute=attribute):
                    root = self.write_report([REMOTE_CASE])
                    summary = root if summary_index is None else root[summary_index]
                    summary.set(attribute, value)
                    self.write_xml(root)
                    with self.assertRaisesRegex(ValueError, message):
                        check_attendance(self.report, "remote")

    def test_empty_and_malformed_junit(self):
        for data in (b"", b"<testsuites><testsuite></testsuites>"):
            with self.subTest(data=data):
                self.report.write_bytes(data)
                with self.assertRaises(ElementTree.ParseError):
                    check_attendance(self.report, "remote")

    def test_internal_and_external_document_types_are_refused(self):
        for encoding in ("utf-8", "utf-16"):
            for declaration in (
                '<!DOCTYPE testsuites [<!ENTITY name "nextest-run">]>',
                '<!DOCTYPE testsuites SYSTEM "file:///does-not-exist">',
            ):
                with self.subTest(encoding=encoding, declaration=declaration):
                    self.report.write_bytes(f"{declaration}<testsuites/>".encode(encoding))
                    with self.assertRaisesRegex(ValueError, "document types are prohibited"):
                        check_attendance(self.report, "remote")

    def test_report_size_is_bounded_before_parsing(self):
        self.report.write_bytes(b" " * (MAX_REPORT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
            check_attendance(self.report, "remote")


if __name__ == "__main__":
    unittest.main()

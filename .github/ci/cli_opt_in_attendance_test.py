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
    "args::parser::sync_managed::tests::signed_recreate_requires_an_independently_selected_pair_and_expiry",
    "sync_preview::managed_command::recreate::tests::prepare_recreate_refuses_oversize_receipt_without_candidate",
    "sync_preview::managed_command::recreate::tests::plan_expiry_preserves_fraction_and_refuses_seconds_overflow",
    (
        "sync_preview::managed_command::export_recreate::tests::"
        "signed_export_report_round_trips_the_exact_members_without_authority"
    ),
    "sync_preview::managed_command::export_recreate::tests::refused_export_has_no_association_or_bundle",
    (
        "assembly::linux::managed_sync::manual_recreate::tests::"
        "manual_recreate_selects_only_the_current_survivor_and_exact_conflict"
    ),
    (
        "assembly::linux::managed_sync::manual_recreate::tests::"
        "manual_recreate_refuses_nonabsence_and_the_absent_peers_read_ceiling"
    ),
)
WINDOWS_BOOTSTRAP_EXPECTED = (
    "args::parser::recovery::windows_bootstrap::tests::windows_bootstrap_parser_requires_exact_independent_selection",
    "windows_bootstrap_inspect::tests::windows_bootstrap_report_projects_only_historical_evidence",
    "windows_bootstrap_inspect::tests::windows_bootstrap_weak_key_refuses_with_no_reported_history",
)
WINDOWS_BOOTSTRAP_DEFAULT_EXPECTED = (
    "args::parser::recovery::tests::inspect_windows_bootstrap_is_hidden_without_the_exact_target_and_feature"
)
WINDOWS_SFTP_CAPTURE_EXPECTED = (
    "assembly::windows_capture::selection::tests::selected_scope_preserves_dns_basis_account_bytes_route_and_raw_path",
    "assembly::windows_capture::selection::tests::full_supervisor_width_changes_commitment_and_same_numbers_cannot_enter",
    "assembly::windows_capture::progress::tests::refused_append_reports_possible_changes_without_a_confirmed_boundary",
    "assembly::windows_capture::progress::tests::dropped_capture_future_preserves_the_previously_confirmed_boundary",
)
WINDOWS_SFTP_PLATFORM_EXPECTED = (
    (
        "windows::read::protected::bootstrap::capture_stage::authenticated::journal::tests::"
        "exact_capture_limit_admits_one_final_byte_and_refuses_overflow"
    ),
    (
        "windows::read::protected::bootstrap::capture_stage::authenticated::journal::tests::"
        "dropping_a_partly_written_append_disallows_reuse_or_terminal_success"
    ),
    (
        "windows::read::protected::bootstrap::capture_stage::authenticated::journal::tests::"
        "next_append_starts_at_the_full_synchronized_predecessor"
    ),
)


SFTP_SOURCE_EXPECTED = (
    "source::tests::scoped_source_checks_live_observation_and_reads_high_offset_short_replies",
    "source::tests::pending::wrong_attempt_or_epoch_cannot_activate_pending_source",
    "source::tests::pending::typed_source_sends_exact_posix_names_for_both_path_roots",
    "source::tests::pending::typed_absolute_source_preserves_leading_slash_on_the_same_handle",
    "source::tests::pending::revoked_or_expired_after_pending_open_refuses_before_callback",
    "source::tests::pending::pending_metadata_activates_exactly_the_same_held_handle",
    "source::tests::pending::oversized_paths_are_refused_before_any_source_request",
    "source::tests::pending::expired_or_retired_attempt_does_not_open_a_remote_handle",
    "source::tests::pending::empty_absolute_root_is_not_a_relative_dot_request",
    "source::tests::pending::callback_refusal_preserves_durable_error_and_discards_stale_success",
    "source::tests::pending::a_matching_binding_still_needs_current_activation_authority",
    "source::tests::key_auth::untrusted_host_or_mismatched_authority_does_not_receive_a_key_offer",
    "source::tests::key_auth::supplied_key_authenticates_once_with_a_verified_authority",
    "source::tests::key_auth::same_host_rekey_keeps_the_authenticated_session",
    "source::tests::key_auth::rejected_key_ends_the_attempt_without_password_or_subsystem_fallback",
    "source::tests::key_auth::async_protected_key_broker_requires_current_grant_before_actual_offer",
    "source::tests::invalid_positive_interval_refuses_before_data_and_retires_scope",
    "source::refused_read_keeps_wire_failure_as_detail_under_the_binding_error",
    "source::only_an_authorized_held_data_read_exposes_the_distinct_timeout",
)


class CliOptInAttendanceTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.report = Path(directory.name) / "junit.xml"

    def write_report(self, cases, siblings=(), *, owner="exacopy-cli"):
        statuses = {"skipped": "0", "failures": "0", "errors": "0"}
        suites = ((owner, cases), *siblings)
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
        self.write_report([*RECREATE_EXPECTED, OTHER_CASE])
        with self.assertRaisesRegex(ValueError, f"unexpected managed-sync-recreate testcases: {OTHER_CASE}$"):
            check_attendance(self.report, "managed-sync-recreate")
        root = self.write_report(RECREATE_EXPECTED)
        ElementTree.SubElement(root[0][0], "skipped")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "managed-sync-recreate")

    def test_windows_bootstrap_requires_every_completed_owning_case(self):
        self.write_report(WINDOWS_BOOTSTRAP_EXPECTED)
        self.assertEqual(
            check_attendance(self.report, "windows-bootstrap-inspect"), sorted(WINDOWS_BOOTSTRAP_EXPECTED),
        )
        for missing in WINDOWS_BOOTSTRAP_EXPECTED:
            with self.subTest(missing=missing):
                present = [name for name in WINDOWS_BOOTSTRAP_EXPECTED if name != missing]
                self.write_report([*present, missing.replace("::tests::", "::other_tests::")])
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "windows-bootstrap-inspect")
        root = self.write_report(WINDOWS_BOOTSTRAP_EXPECTED)
        ElementTree.SubElement(root[0][0], "skipped")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "windows-bootstrap-inspect")

    def test_windows_bootstrap_default_guard_requires_the_workspace_cli_suite(self):
        self.write_report((WINDOWS_BOOTSTRAP_DEFAULT_EXPECTED,), (("exacopy-model", (OTHER_CASE,)),))
        self.assertEqual(
            check_attendance(self.report, "windows-bootstrap-default"), [WINDOWS_BOOTSTRAP_DEFAULT_EXPECTED],
        )
        self.write_report((OTHER_CASE,), (("exacopy-cli::command", (WINDOWS_BOOTSTRAP_DEFAULT_EXPECTED,)),))
        with self.assertRaisesRegex(ValueError, f"required testcases missing: {WINDOWS_BOOTSTRAP_DEFAULT_EXPECTED}$"):
            check_attendance(self.report, "windows-bootstrap-default")

    def test_windows_sftp_capture_requires_all_seven_cases_in_their_owning_suites(self):
        cli = WINDOWS_SFTP_CAPTURE_EXPECTED
        platform = WINDOWS_SFTP_PLATFORM_EXPECTED
        self.write_report(cli, (("exacopy-platform", platform),))
        self.assertEqual(check_attendance(self.report, "windows-sftp-capture"), sorted(cli + platform))
        for owner, cases in (("exacopy-cli", cli), ("exacopy-platform", platform)):
            for missing in cases:
                with self.subTest(missing=missing):
                    lookalike = missing.replace("::tests::", "::other_tests::")
                    changed = tuple(lookalike if name == missing else name for name in cases)
                    selected_cli, selected_platform = (changed, platform) if owner == "exacopy-cli" else (cli, changed)
                    self.write_report(selected_cli, (("exacopy-platform", selected_platform),))
                    with self.assertRaisesRegex(ValueError, f"required {owner} testcases missing: {missing}$"):
                        check_attendance(self.report, "windows-sftp-capture")
        self.write_report((platform[0], *cli[1:]), (("exacopy-platform", (cli[0], *platform[1:])),))
        with self.assertRaisesRegex(ValueError, "required exacopy-cli testcases missing"):
            check_attendance(self.report, "windows-sftp-capture")

    def test_windows_sftp_capture_refuses_extra_suites_cases_and_unsuccessful_evidence(self):
        cli = WINDOWS_SFTP_CAPTURE_EXPECTED
        platform = WINDOWS_SFTP_PLATFORM_EXPECTED
        for siblings in ((), (("exacopy-platform", platform), ("exacopy-cli::windows_sftp_capture", (OTHER_CASE,)))):
            with self.subTest(siblings=siblings):
                self.write_report(cli, siblings)
                with self.assertRaisesRegex(ValueError, "expected exactly the CLI and platform"):
                    check_attendance(self.report, "windows-sftp-capture")
        self.write_report(cli, (("exacopy-platform", (*platform, OTHER_CASE)),))
        with self.assertRaisesRegex(ValueError, "unexpected exacopy-platform testcases"):
            check_attendance(self.report, "windows-sftp-capture")
        root = self.write_report(cli, (("exacopy-platform", platform),))
        ElementTree.SubElement(root[1][0], "skipped")
        self.write_xml(root)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "windows-sftp-capture")

    def test_sftp_source_requires_every_case_from_the_adapter_library(self):
        owner = "exacopy-sftp"
        xml = self.write_report(SFTP_SOURCE_EXPECTED, owner=owner)
        self.assertEqual(check_attendance(self.report, "sftp-source"), sorted(SFTP_SOURCE_EXPECTED))
        xml[0][0].set("classname", "exacopy-cli")
        self.write_xml(xml)
        with self.assertRaisesRegex(ValueError, "expected a named exacopy-sftp testcase"):
            check_attendance(self.report, "sftp-source")
        self.write_report(SFTP_SOURCE_EXPECTED)
        with self.assertRaisesRegex(ValueError, "expected the exacopy-sftp unit-test suite"):
            check_attendance(self.report, "sftp-source")
        xml = self.write_report(SFTP_SOURCE_EXPECTED, owner=owner)
        ElementTree.SubElement(xml[0][0], "skipped")
        self.write_xml(xml)
        with self.assertRaisesRegex(ValueError, "lacks a successful execution record"):
            check_attendance(self.report, "sftp-source")
        for missing in SFTP_SOURCE_EXPECTED:
            with self.subTest(missing=missing):
                self.write_report([case for case in SFTP_SOURCE_EXPECTED if case != missing], owner=owner)
                with self.assertRaisesRegex(ValueError, f"required testcases missing: {missing}$"):
                    check_attendance(self.report, "sftp-source")
        self.write_report([*SFTP_SOURCE_EXPECTED, "source::unrelated"], owner=owner)
        with self.assertRaisesRegex(ValueError, "unexpected sftp-source testcases"):
            check_attendance(self.report, "sftp-source")
        self.write_report([*SFTP_SOURCE_EXPECTED, SFTP_SOURCE_EXPECTED[0]], owner=owner)
        with self.assertRaisesRegex(ValueError, "duplicate testcase"):
            check_attendance(self.report, "sftp-source")

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

"""Verify completed CLI unit tests in the pinned nextest JUnit report."""

import argparse
from pathlib import Path
from xml.etree import ElementTree

MAX_REPORT_BYTES = 1024 * 1024
CLI_SUITE = "exacopy-cli"
TRANSFER_SUITE = "exacopy-transfer"
REMOTE_CASE = (
    "assembly::linux::remote_continued::tests::"
    "actual_signed_kind40_must_form_the_exact_clean_successor"
)
REMOTE_PREFLIGHT_CASE = (
    "assembly::linux::remote_continued::tests::hosted_witness::preflight::tests::"
    "original_capture_budget_and_native_projection_match_signed_next_pass"
)
SSH_SESSION_CASES = {
    "assembly::ssh_session::tests::host_and_route_admission_precede_credential_offer_liveness",
    "assembly::ssh_session::tests::protected_key_worker_rechecks_the_same_offer_before_reading",
}
PUBLIC_STAGE_CASES = {
    "args::parser::tests::new_commands_keep_raw_input_and_baseline_paths",
    "args::parser::tests::verification_defaults_to_human_and_defers_invalid_path_values",
    "args::parser::tests::invalid_manifest_cli_syntax_never_returns_a_command",
    "args::parser::tests::help_reports_explicit_verification_baseline_and_creation_output",
    "args::parser::tests::plan_accepts_one_explicit_profile_and_output_and_refuses_unknown_policy",
    "args::parser::tests::public_stage_command_availability_follows_its_exact_feature",
    "args::parser::tests::public_stage_selection_keeps_owner_key_separate_from_legacy_recovery",
    "public_stage_inspect::tests::public_stage_reports_checked_absence_without_inventing_evidence",
    "public_stage_inspect::tests::public_stage_journal_reports_only_the_last_accepted_observation",
    "public_stage_inspect::tests::accepted_owner_key_is_canonical_and_refusals_do_not_reveal_paths",
}
WITNESSED_RESUME_CASES = {
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
}
APFS_CASES = {
    "args::parser::recovery::apfs::tests::inspect_apfs_requires_independent_exact_selectors_and_keeps_raw_container_bytes",
    "apfs_inspect::report::tests::apfs_inspection_keeps_reconciliation_separate_from_history_and_receipt",
    "assembly::macos::job::tests::cli_inspection::apfs_inspect_dispatch_binds_the_independent_selection_and_preserves_the_job",
}
APFS_DEFAULT_CASE = "args::parser::recovery::tests::inspect_apfs_is_hidden_without_the_exact_target_and_feature"
MANAGED_SYNC_RECREATE_CASES = {
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
}
WINDOWS_BOOTSTRAP_CASES = {
    "args::parser::recovery::windows_bootstrap::tests::windows_bootstrap_parser_requires_exact_independent_selection",
    "windows_bootstrap_inspect::tests::windows_bootstrap_report_projects_only_historical_evidence",
    "windows_bootstrap_inspect::tests::windows_bootstrap_weak_key_refuses_with_no_reported_history",
}
WINDOWS_BOOTSTRAP_DEFAULT_CASE = (
    "args::parser::recovery::tests::inspect_windows_bootstrap_is_hidden_without_the_exact_target_and_feature"
)
REQUIRED_CASES = {
    "remote": {REMOTE_CASE, REMOTE_PREFLIGHT_CASE} | SSH_SESSION_CASES,
    "public-stage": PUBLIC_STAGE_CASES,
    "witnessed-resume": WITNESSED_RESUME_CASES,
    "apfs-copy": APFS_CASES,
    "apfs-default": {APFS_DEFAULT_CASE},
    "managed-sync-recreate": MANAGED_SYNC_RECREATE_CASES,
    "windows-bootstrap-inspect": WINDOWS_BOOTSTRAP_CASES,
    "windows-bootstrap-default": {WINDOWS_BOOTSTRAP_DEFAULT_CASE},
}


class NoDoctype(ElementTree.TreeBuilder):
    def doctype(self, name, public_id, system_id):
        raise ValueError("JUnit document types are prohibited")


def check_attendance(report, lane):
    required = REQUIRED_CASES[lane]
    with report.open("rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("JUnit report exceeds 1 MiB")

    root = ElementTree.fromstring(data, parser=ElementTree.XMLParser(target=NoDoctype()))
    if root.tag != "testsuites" or root.get("name") != "nextest-run":
        raise ValueError("expected a nextest JUnit report")
    if lane not in ("apfs-copy", "apfs-default", "windows-bootstrap-default") and len(root) != 1:
        raise ValueError("expected one nextest JUnit suite")

    suites = {}
    for suite in root:
        name = suite.get("name")
        if suite.tag != "testsuite" or not name or name in suites:
            raise ValueError("expected unique named nextest JUnit suites")
        if lane == "apfs-copy" and name.partition("::")[0] not in (CLI_SUITE, TRANSFER_SUITE):
            raise ValueError(f"unexpected APFS JUnit suite: {name}")
        suites[name] = suite
    if CLI_SUITE not in suites:
        raise ValueError(f"expected the {CLI_SUITE} unit-test suite")
    if lane == "apfs-copy" and len(suites.get(TRANSFER_SUITE, ())) == 0:
        raise ValueError(f"expected the {TRANSFER_SUITE} unit-test suite with completed cases")

    check_summary(root, sum(map(len, suites.values())))
    cases = {name: checked_cases(suite, name) for name, suite in suites.items()}
    attended = cases[CLI_SUITE]

    missing = required - attended
    if missing:
        raise ValueError(f"required testcases missing: {', '.join(sorted(missing))}")
    if lane == "public-stage" and (unexpected := attended - required):
        raise ValueError(f"unexpected public-stage testcases: {', '.join(sorted(unexpected))}")
    return sorted(required)


def check_summary(summary, length):
    if summary.get("tests") != str(length):
        raise ValueError("JUnit test count does not match the suite")
    if any(summary.get(status) != "0" for status in ("skipped", "failures", "errors")):
        raise ValueError("JUnit reports skipped or unsuccessful tests")


def checked_cases(suite, suite_name):
    check_summary(suite, len(suite))
    attended = set()
    for case in suite:
        name = case.get("name")
        if case.tag != "testcase" or case.get("classname") != suite_name or not name:
            raise ValueError(f"expected a named {suite_name} testcase")
        if name in attended:
            raise ValueError(f"duplicate testcase {name!r}")
        # These CI profiles disable retries and omit output from successful tests.
        if len(case) or not case.get("timestamp") or not case.get("time"):
            raise ValueError(f"testcase {name!r} lacks a successful execution record")
        attended.add(name)
    return attended


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=REQUIRED_CASES)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        attended = check_attendance(args.report, args.lane)
    except (OSError, ValueError, LookupError, ElementTree.ParseError) as error:
        parser.exit(1, f"CLI {args.lane} attendance failed: {error}\n")
    for name in attended:
        print(f"Passed {CLI_SUITE}::{name}")


if __name__ == "__main__":
    main()

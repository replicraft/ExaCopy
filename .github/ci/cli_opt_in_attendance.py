"""Verify completed CLI unit tests in the pinned nextest JUnit report."""

import argparse
from pathlib import Path
from xml.etree import ElementTree

MAX_REPORT_BYTES = 1024 * 1024
CLI_SUITE = "exacopy-cli"
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
REQUIRED_CASES = {
    "remote": {REMOTE_CASE, REMOTE_PREFLIGHT_CASE} | SSH_SESSION_CASES,
    "public-stage": PUBLIC_STAGE_CASES,
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
    if root.tag != "testsuites" or root.get("name") != "nextest-run" or len(root) != 1:
        raise ValueError("expected one nextest JUnit suite")
    suite = root[0]
    if suite.tag != "testsuite" or suite.get("name") != CLI_SUITE:
        raise ValueError(f"expected the {CLI_SUITE} unit-test suite")

    for summary in (root, suite):
        if summary.get("tests") != str(len(suite)):
            raise ValueError("JUnit test count does not match the suite")
        if any(summary.get(status) != "0" for status in ("skipped", "failures", "errors")):
            raise ValueError("JUnit reports skipped or unsuccessful tests")

    attended = set()
    for case in suite:
        name = case.get("name")
        if case.tag != "testcase" or case.get("classname") != CLI_SUITE or not name:
            raise ValueError(f"expected a named {CLI_SUITE} testcase")
        if name in attended:
            raise ValueError(f"duplicate testcase {name!r}")
        # These CI profiles disable retries and omit output from successful tests.
        if len(case) or not case.get("timestamp") or not case.get("time"):
            raise ValueError(f"testcase {name!r} lacks a successful execution record")
        attended.add(name)

    missing = required - attended
    if missing:
        raise ValueError(f"required testcases missing: {', '.join(sorted(missing))}")
    if lane == "public-stage" and (unexpected := attended - required):
        raise ValueError(f"unexpected public-stage testcases: {', '.join(sorted(unexpected))}")
    return sorted(required)


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

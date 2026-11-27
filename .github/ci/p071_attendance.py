"""Verify exact attendance in the pinned P-071 Linux reservation fixture."""

import argparse
from pathlib import Path
import re

MAX_REPORT_BYTES = 1024 * 1024
PREFIX = "linux::recovery::writer::witness_reservation::tests::"
CASES = frozenset(PREFIX + name for name in (
    "allocation_may_refresh_write_times_but_not_other_selected_fields",
    "native_plan_checks_the_positive_byte_and_sequence_bounds",
    "separate_gate_holds_through_syscall_and_refusal_runs_no_effect",
    "native_allocation_preserves_the_named_segment_and_anonymous_eof",
    "only_a_submitted_journal_allocation_latches_the_lease_even_on_syscall_error",
    "coverage::anonymous_receipt_inspection_refuses_a_named_empty_private_record",
    "coverage::journal_apertures_keep_independent_offsets_and_refuse_a_grown_eof",
    "coverage::reservation_errors_keep_the_refusal_phase_and_typed_cause",
))
OUTCOME = re.compile(r"test ([A-Za-z_0-9:]+) \.\.\. ok")
SUMMARY = re.compile(
    rf"test result: ok\. {len(CASES)} passed; 0 failed; 0 ignored; 0 measured; "
    r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s",
)


def check_output(data):
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("P-071 report exceeds 1 MiB")
    lines = data.decode("utf-8").split("\n")
    runs = [index for index, line in enumerate(lines) if line.startswith("running ")]
    summaries = [index for index, line in enumerate(lines) if line.startswith("test result:")]
    if len(runs) != 1 or lines[runs[0]] != f"running {len(CASES)} tests":
        raise ValueError("expected one exact P-071 run header")
    if len(summaries) != 1 or not SUMMARY.fullmatch(lines[summaries[0]]):
        raise ValueError("expected one exact successful P-071 result summary")
    start, end = runs[0], summaries[0]
    if end <= start:
        raise ValueError("P-071 result summary precedes execution")
    # --show-output can print the successful cases and their captured stdout
    # afterward. Only libtest's outcome rows belong to the attendance window.
    outcomes_end = next((i for i in range(start + 1, end) if lines[i] == "successes:"), end)
    attended = set()
    for index, line in enumerate(lines):
        if not line.startswith("test ") or line.startswith("test result:"):
            continue
        match = OUTCOME.fullmatch(line)
        if not start < index < outcomes_end or match is None:
            raise ValueError("P-071 report has an unsuccessful, malformed, or misplaced outcome")
        name = match[1]
        if name not in CASES:
            raise ValueError(f"unexpected P-071 testcase {name!r}")
        if name in attended:
            raise ValueError(f"duplicate P-071 testcase {name!r}")
        attended.add(name)
    if missing := CASES - attended:
        raise ValueError(f"missing P-071 testcases: {', '.join(sorted(missing))}")
    return sorted(attended)


def check_attendance(report):
    with report.open("rb") as stream:
        return check_output(stream.read(MAX_REPORT_BYTES + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        attended = check_attendance(args.report)
    except (OSError, ValueError) as error:
        parser.exit(1, f"P-071 attendance failed: {error}\n")
    print(f"Confirmed attendance for all {len(attended)} exact P-071 cases")


if __name__ == "__main__":
    main()

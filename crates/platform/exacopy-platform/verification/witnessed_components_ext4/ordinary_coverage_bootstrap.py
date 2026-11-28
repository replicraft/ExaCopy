"""Validate the selected ordinary Linux CLI coverage inputs."""

from pathlib import Path
import re
from xml.etree import ElementTree

from run import ext4

require = ext4.require

BOOTSTRAP_SUITE = "exacopy-cli::job_bootstrap"
COPY_SUITE = "exacopy-cli::linux_copy"
CLI_MAIN = "apps/exacopy-cli/src/main.rs"
COPY_OBJECT = re.compile(r"debug/build/exacopy-cli/([0-9a-f]{16})/out/linux_copy-\1")
CHILD_OBJECT = re.compile(r"debug/build/exacopy-cli/[0-9a-f]{16}/out/exacopy")
CHILD_LAUNCH = re.compile(r"debug/exacopy")
BOOTSTRAP_OBJECT = re.compile(r"debug/build/exacopy-cli/([0-9a-f]{16})/out/job_bootstrap-\1")
BOOTSTRAP_CASES = {
    "a_private_looking_incumbent_job_is_never_adopted",
    "a_token_reusing_the_job_or_profile_identity_is_rejected_before_creation",
    "a_repeated_bootstrap_preserves_the_original_owner_and_journal_records",
    "copy::conflicting_destination_capabilities_refuse_before_private_job_creation",
    "copy::late_preflight_conflict_and_changed_source_create_no_private_job",
    "copy::terminal_journal::copy_refuses_a_corrupt_prefix_after_receipt_commitment_and_preserves_publication",
    "copy::journaled_copy_persists_a_receipt_bound_to_verified_bytes_and_observed_publication",
    "journal_names::fresh_writer_checks_live_names_again_after_reading_the_exact_prefix",
    "copy::receipt_readback::copy_refuses_a_same_byte_receipt_rebind_without_altering_the_public_result",
    "journal_names::fresh_writer_refuses_each_same_byte_native_alias_rebound",
    "verifies_the_persisted_signed_owner_and_first_preparation_frame",
}


COPY_CASES = {
    "arguments::escaped_raw_paths_and_trailing_options_keep_their_original_meaning",
    "arguments::incomplete_or_duplicate_copy_grants_create_no_job_and_preserve_existing_objects",
    "arguments::incomplete_source_grants_preserve_an_existing_recovery_journal",
    "concurrent_processes_cannot_replace_the_winner",
    "failed_report_output_keeps_the_committed_copy_and_names_the_job",
    "publishes_raw_name_and_retains_authenticated_job_and_matching_receipt",
    "recovery::a_different_profile_cannot_authenticate_a_retained_job",
    "recovery::finishes_a_published_copy_without_replacing_the_target",
    "recovery::reports_current_receipt_and_detects_a_same_length_changed_target",
    "refuses_incumbents_symlinks_and_source_aliases_without_starting_a_job",
    "rejects_malformed_and_unsafe_profiles_and_preserves_the_key",
    "resume::resumes_a_checkpointed_copy_and_repeats_with_the_same_receipt",
    "retry::rejects_wrong_source_grants_and_changed_source_bytes_without_leaking_paths",
    "retry::reports_conflict_and_preserves_both_inodes",
    "retry::reports_reconciliation_for_a_torn_journal_without_publication",
    "retry::resume_leaves_an_active_intent_for_explicit_retry",
    "retry::retries_a_retained_inode_and_repeats_without_changing_the_receipt",
}
CLI_SUITES = {BOOTSTRAP_SUITE: BOOTSTRAP_CASES, COPY_SUITE: COPY_CASES}


def owner_rows(rows):
    owner = re.compile(r"(^|/)crates/(foundation/exacopy-core/src/component\.rs$|"
                       r"interfaces/exacopy-endpoint/src/|platform/exacopy-platform/src/)")
    return {name: counts for name, counts in rows.items() if owner.search(name)}


def junit_suites(raw):
    try:
        return ElementTree.fromstring(raw).findall("testsuite")
    except ElementTree.ParseError as error:
        raise ValueError("invalid instrumented Nextest JUnit") from error


def owner_attendance(suites):
    packages = {"exacopy-core", "exacopy-endpoint", "exacopy-platform"}
    seen = set()
    for suite in suites:
        name = suite.attrib["name"]
        if name.split("::", 1)[0] not in packages:
            continue
        require(all(suite.get(field) == "0" for field in ("failures", "errors", "skipped")),
                "instrumented Nextest owner suite lacks success")
        for case in suite.findall("testcase"):
            item = (name, case.attrib["name"])
            require(case.get("classname") == name and not list(case) and item not in seen,
                    "instrumented Nextest owner case lacks unique success")
            seen.add(item)
    require({suite.split("::", 1)[0] for suite, _ in seen} == packages,
            "instrumented Nextest owner attendance is incomplete")
    return seen


def cli_attendance(raw):
    suites = [suite for suite in junit_suites(raw)
              if suite.get("name", "").startswith("exacopy-cli")]
    require(len(suites) == len(CLI_SUITES)
            and {suite.get("name") for suite in suites} == CLI_SUITES.keys(),
            "instrumented Nextest CLI test binaries differ")
    for suite in suites:
        name = suite.attrib["name"]
        expected = CLI_SUITES[name]
        cases = suite.findall("testcase")
        require(suite.get("tests") == str(len(expected))
                and all(suite.get(field) == "0" for field in ("failures", "errors", "skipped"))
                and len(cases) == len(expected)
                and {case.get("name") for case in cases} == expected
                and all(case.get("classname") == name and not list(case) for case in cases),
                f"instrumented Nextest attendance differs for {name}")


def exact_object(objects, target, pattern, name):
    matches = []
    for entry in objects:
        path = Path(entry["path"])
        require(path.is_relative_to(target), "ordinary LLVM object escaped campaign target")
        if pattern.fullmatch(path.relative_to(target).as_posix()):
            matches.append(entry)
    require(len(matches) == 1, f"expected one instrumented {name} ELF")
    return matches[0]


def bootstrap_object(objects, target):
    return exact_object(objects, target, BOOTSTRAP_OBJECT, "job_bootstrap")


def copy_objects(objects, target):
    test = exact_object(objects, target, COPY_OBJECT, "linux_copy")
    child = exact_object(objects, target, CHILD_OBJECT, "exacopy child")
    launch = exact_object(objects, target, CHILD_LAUNCH, "exacopy launch")
    require((child["size"], child["sha256"]) == (launch["size"], launch["sha256"]),
            "ordinary exacopy launch differs from its linked child ELF")
    return test, child, launch


def child_main_coverage(rows, root):
    name = str(root / CLI_MAIN)
    counted, covered = rows.get(name, (0, 0))
    require(0 < covered <= counted, "ordinary indexed data lacks executed exacopy child main")
    return {"source": CLI_MAIN, "count": counted, "covered": covered}

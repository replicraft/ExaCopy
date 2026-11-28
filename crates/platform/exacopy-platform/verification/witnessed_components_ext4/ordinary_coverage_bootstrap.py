"""Validate the additional ordinary Linux CLI coverage input."""

from pathlib import Path
import re
from xml.etree import ElementTree

from run import ext4

require = ext4.require

BOOTSTRAP_SUITE = "exacopy-cli::job_bootstrap"
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


def bootstrap_attendance(raw):
    suites = [suite for suite in junit_suites(raw)
              if suite.get("name", "").startswith("exacopy-cli")]
    require(len(suites) == 1 and suites[0].get("name") == BOOTSTRAP_SUITE,
            "instrumented Nextest CLI test binary differs")
    suite = suites[0]
    cases = suite.findall("testcase")
    require(suite.get("tests") == str(len(BOOTSTRAP_CASES))
            and all(suite.get(field) == "0" for field in ("failures", "errors", "skipped"))
            and len(cases) == len(BOOTSTRAP_CASES)
            and {case.get("name") for case in cases} == BOOTSTRAP_CASES
            and all(case.get("classname") == BOOTSTRAP_SUITE and not list(case) for case in cases),
            "instrumented Nextest job_bootstrap attendance differs")


def bootstrap_object(objects, target):
    matches = [entry for entry in objects
               if BOOTSTRAP_OBJECT.fullmatch(Path(entry["path"]).relative_to(target).as_posix())]
    require(len(matches) == 1, "expected one instrumented job_bootstrap ELF")
    return matches[0]

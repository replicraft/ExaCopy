#!/usr/bin/env python3
"""Check structural linkage and recorded measurements without rerunning a reference."""

import json
from pathlib import Path
import re

from common import MACOS_ACL_FIXTURE, ROOT, digest, require
from run import MIB, PROTOCOL, summarize


REQUIRED_TARGETS = {
    "adb", "beyond-compare-pro", "fastcopy", "freefilesync", "kopia", "openmtp",
    "cmp", "openssh", "restic", "rsync", "teracopy", "winscp", "wireguard",
}

# The first measured revision used the helper before its shared fixture path was fixed.
HISTORICAL_RUNNER = {
    "d82ce08b78f770e500de9b2c7965f24d625b757a": (
        "b568c1c52621826f6665dbacceca68638d8bcc74af4063c5434b090e82aeaa12",
        "f3a13b225dde78a1b84fd95420f96d9b55833ea0ef14c01d25ec45ef59e02674",
    ),
}


def read_json(path):
    with path.open() as stream:
        return json.load(stream)


def is_sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def evidence_path(directory, filename):
    root = (directory / "evidence").resolve()
    path = (directory / filename).resolve()
    require(path.is_relative_to(root) and path.is_file(), f"missing or out-of-scope evidence: {filename}")
    return path


def check_evidence(path):
    report = read_json(path)
    require(report["schema_version"] == 1 and report["protocol"] == PROTOCOL and report["outcome"] == "passed",
            f"ineligible evidence: {path}")
    config = report["configuration"]
    require(re.fullmatch(r"[0-9a-f]{40}", config["source_revision"]) is not None, f"missing revision: {path}")
    require(all(is_sha256(config[key]) for key in ("exacopy_binary_sha256", "cargo_lock_sha256", "cmp_sha256")),
            f"missing artifact digest: {path}")
    recorded = (config["runner_sha256"], config["fixture_helper_sha256"])
    current = tuple(digest(ROOT / "tools/reference" / name) for name in ("run.py", "common.py"))
    historical = HISTORICAL_RUNNER.get(config["source_revision"])
    require(recorded == current or recorded == historical, f"runner provenance drift: {path}")
    return report


# The retained v1 differential suite specifies the generated fixture and witness for each case.
# Keep the expected cases independent of the recorded outcomes and the production comparator.
DIFFERENTIAL_CASES = {
    "empty-equal": (0, 0, None, False),
    "binary-equal": (3 * MIB, 3 * MIB, None, False),
    "first-byte": (3 * MIB, 3 * MIB, 0, False),
    "middle-byte": (3 * MIB, 3 * MIB, 3 * MIB // 2, False),
    "final-byte": (3 * MIB, 3 * MIB, 3 * MIB - 1, False),
    "shorter": (4096, 4095, None, False),
    "sparse-byte": (6 * MIB, 6 * MIB, 4 * MIB + 17, True),
}


def check_diff_header(report):
    return (report["schema"], report["schema_version"], report["relation"]) == (
        "exacopy.cli.diff", "1.0", "bytes")


def rsync_transfer_item(item):
    return isinstance(item, str) and len(item) == 11 and item.startswith(">f")


def check_differential(evidence):
    cases = evidence["cases"]
    require(len(cases) == len(DIFFERENTIAL_CASES) and {case["case"] for case in cases} == DIFFERENTIAL_CASES.keys(),
            "missing or duplicate differential fixture")
    for case in cases:
        name = case["case"]
        left, right, offset, sparse = DIFFERENTIAL_CASES[name]
        require((case["left_bytes"], case["right_bytes"], case["first_byte"]) == (left, right, offset)
                and case["sparse_fixture"] is sparse, f"wrong fixture for {name}")
        different = left != right or offset is not None
        hashes = case["sha256"]
        require(len(hashes) == 2 and all(is_sha256(item) for item in hashes)
                and (hashes[0] != hashes[1]) is different, f"wrong fixture digests for {name}")
        require(case["fixture_preserved"] is True, f"fixture changed for {name}")
        require(case["cmp_exit"] == int(different), f"cmp result contradicts fixture for {name}")
        require(case["rsync_exit"] == 0 and (
            rsync_transfer_item(case["rsync_itemized_change"]) if different else case["rsync_itemized_change"] == ""
        ), f"rsync result contradicts fixture for {name}")
        reports = case["exa_copy"]
        require(set(reports) == {"1", "4", "16"}, f"missing worker report for {name}")
        for workers, run in reports.items():
            report = run["report"]
            require(run["exit_code"] == int(different) and check_diff_header(report)
                    and report["complete"] is True and report["consistency"] == "live_observed",
                    f"invalid ExaCopy report for {name} with {workers} workers")
            if different:
                expected = ({"kind": "length", "left": str(left), "right": str(right)} if left != right
                            else {"kind": "first_byte", "offset": str(offset)})
                require(report["result"] == "different" and report["difference"] == expected,
                        f"wrong ExaCopy difference witness for {name} with {workers} workers")
            else:
                require(report["result"] == "equal" and report["length"] == str(left),
                        f"incorrect ExaCopy equality for {name} with {workers} workers")
    control = evidence["symlink_control"]
    report = control["exa_copy"]
    require(control["cmp_exit"] == 0 and control["exa_copy_exit"] == 2 and check_diff_header(report)
            and report["result"] == "inconclusive" and report["complete"] is False
            and report["error"]["code"] == "E_OPEN_INPUT", "missing final symlink refusal")


def check_copy_evidence(evidence, count):
    control = evidence["incumbent_control"]
    require(control["exacopy_exit"] == 3 and control["exacopy_error"] == "E_CONFLICT"
            and control["rsync_exit"] == 0 and control["rsync_itemized_change"] == ""
            and control["source_and_incumbent_preserved"] is True, "missing incumbent-preservation evidence")
    reference = evidence["rsync_copy"]
    require(reference["reference_exit"] == 0 and reference["cmp_exit"] == 0 and rsync_transfer_item(reference["item"]),
            "rsync absent-target copy did not pass the byte oracle")
    cases = evidence["workloads"]
    require(len(cases) == 2 and {(case["case"], case["bytes"]) for case in cases}
            == {("small-copy", 4096), ("large-copy", 64 * MIB)}, "wrong verified copy workloads")
    for case in cases:
        assurance = case["assurance"]
        require(assurance == {
            "schema": "exacopy.cli.copy", "schema_version": "1.0",
            "publication": "published", "completed": 1, "pending": 0, "verification": "hash_readback",
            "consistency": "live_observed", "durability": "unconfirmed", "preservation": "preserve",
            "redundancy": "independent_writes", "metadata": "complete_for_policy",
        } and is_sha256(case["sha256"]), f"invalid verified copy report for {case['case']}")
        check_samples(case["verified_samples"], case["summary"], count)


def check_reference_profile(target, profile, configuration, lane):
    platform = configuration["platform"]
    os_profile = (platform["os"], platform["filesystem"])
    platform_matches = all(platform[key] and re.search(
        rf"(?<![\w.]){re.escape(platform[key])}(?![\w.])", profile["platform"]) for key in ("version", "machine"))
    require(os_profile in {("Darwin", "apfs"), ("Linux", "ext4")}
            and (lane != "copy" or os_profile == ("Linux", "ext4"))
            and platform["filesystem"] in profile["filesystem"].lower()
            and platform_matches,
            f"evidence platform disagrees with {profile['id']}")
    require(is_sha256(configuration["rsync_sha256"]), f"missing rsync digest for {profile['id']}")
    if target == "rsync":
        version = re.fullmatch(r"rsync\s+version (\S+)\s+protocol version (\d+)", configuration["rsync_version"])
        expected = f"{version[1]}, protocol version {version[2]} reported by binary" if version else ""
    else:
        cmp_version = configuration["cmp_version"]
        if os_profile[0] == "Darwin":
            version = re.search(r"PROJECT:(patch_cmds-\d+)\b", cmp_version)
            expected = f"Apple {version[1]}" if version else ""
        else:
            version = re.fullmatch(r"cmp \(GNU diffutils\) (\S+)", cmp_version)
            expected = f"GNU diffutils {version[1]}" if version else ""
    require(expected == profile["reference_version"], f"reference version disagrees with {profile['id']}")


def check_prior_attempt(path, report):
    attempt = read_json(path)
    config = report["configuration"]
    require(attempt["schema_version"] == 1 and attempt["protocol"] == PROTOCOL
            and attempt["outcome"] in {"blocked", "failed"} and attempt["lane"] == report["lane"]
            and attempt["source_revision"] == config["source_revision"]
            and attempt["binary_sha256"] == config["exacopy_binary_sha256"]
            and attempt["filesystem"] == config["platform"]["filesystem"]
            and attempt["copy_result"]["exit_code"] != 0 and is_sha256(attempt["raw_log_sha256"]),
            f"invalid retained failed reference attempt: {path}")


def check_startup_probe(path, target, profile):
    report = read_json(path)
    # This startup-only probe predates the versioned paired runner and has its own record shape.
    require(target == "freefilesync" and report["outcome"] == "blocked"
            and report["reference_version"] == profile["reference_version"].split()[0]
            and report["reference_file_sha256"] and all(map(is_sha256, report["reference_file_sha256"].values()))
            and report["processes"] and all(run["exit"] != 0 or run["timed_out"]
                                            for run in report["processes"].values()),
            f"invalid retained startup probe: {path}")


def check_compatibility(directory=ROOT / "docs/specs/compatibility"):
    inventory = read_json(directory / "inventory.v1.json")
    require(inventory["schema_version"] == 1, "unknown compatibility inventory schema")
    targets = inventory["targets"]
    ids = {target["id"] for target in targets}
    require(len(ids) == len(targets) and REQUIRED_TARGETS.issubset(ids), "missing or duplicate compatibility target")
    classified_evidence = set()
    for target in targets:
        target_id = target["id"]
        require(target["primary_sources"], f"missing reference provenance: {target_id}")
        profiles = target["profiles"]
        require(profiles and len({profile["id"] for profile in profiles}) == len(profiles),
                f"missing or duplicate profiles: {target_id}")
        for profile in profiles:
            profile_id = profile["id"]
            require(profile["acceptance"] and all(re.fullmatch(r"A-\d{3}", id) for id in profile["acceptance"]),
                    f"missing acceptance IDs: {profile_id}")
            require(all(profile[key] for key in (
                "reference_version", "platform", "filesystem", "configuration_and_invocation",
                "fixtures", "expected_behavior", "actual_exacopy_behavior", "reproduction",
            )), f"incomplete reference profile: {profile_id}")
            require(bool(profile["known_deviation"]) == bool(profile["deviation_rationale"]),
                    f"unexplained deviation in {profile_id}")
            if profile["status"] == "executed_pass":
                path = evidence_path(directory, profile["evidence"])
                report = check_evidence(path)
                classified_evidence.add(path)
                lane = report["lane"]
                require((target_id, lane) in {("cmp", "differential"), ("rsync", "differential"), ("rsync", "copy")},
                        f"unexpected target and evidence lane for {profile_id}")
                require((profile_id == "local-copy-to-absent-and-incumbent") == (lane == "copy"),
                        f"wrong evidence lane for {profile_id}")
                config = report["configuration"]
                check_reference_profile(target_id, profile, config, lane)
                if lane == "differential":
                    check_differential(report["evidence"])
                else:
                    count = config["repeats"]
                    require(type(count) is int and 5 <= count <= 30, "invalid copy evidence trial count")
                    check_copy_evidence(report["evidence"], count)
                if "prior_attempt" in profile:
                    path = evidence_path(directory, profile["prior_attempt"])
                    check_prior_attempt(path, report)
                    classified_evidence.add(path)
                require("startup_probe" not in profile, f"expected paired evidence in {profile_id}")
            else:
                require(profile["status"] == "not_executed" and profile["evidence"] is None
                        and "prior_attempt" not in profile,
                        f"unrecognized status or an unclassified artifact: {profile_id}")
                if "startup_probe" in profile:
                    path = evidence_path(directory, profile["startup_probe"])
                    check_startup_probe(path, target_id, profile)
                    classified_evidence.add(path)
    retained_evidence = {path.resolve() for path in (directory / "evidence").rglob("*.json")}
    unclassified = retained_evidence - classified_evidence
    require(not unclassified, f"reference evidence has no classified profile: {sorted(unclassified)}")


def check_samples(samples, summary, count):
    require(len(samples) == count, "measured trial count differs")
    require(all(set(sample) == {"elapsed_ns", "user_cpu_ns", "system_cpu_ns", "peak_rss_bytes"}
                and sample["elapsed_ns"] > 0 and sample["peak_rss_bytes"] > 0
                and min(sample.values()) >= 0 for sample in samples), "invalid trial measurements")
    require(summary == summarize(samples), "stored summary differs from the raw trials")


def check_recovery_performance(path, minimum_trials):
    report = read_json(path)
    require(report["schema_version"] == 1 and report["protocol"] == "exacopy-linux-resume-v1"
            and report["outcome"] == "passed", f"ineligible recovery evidence: {path}")
    config = report["configuration"]
    require(re.fullmatch(r"[0-9a-f]{40}", config["source_revision"]) is not None,
            f"missing recovery revision: {path}")
    require(all(re.fullmatch(r"[0-9a-f]{64}", config[key])
                for key in ("cargo_lock_sha256", "exacopy_binary_sha256")),
            f"missing recovery artifact digest: {path}")
    current_helpers = {name: digest(ROOT / "tools/reference" / name) for name in ("common.py", "run.py")}
    require(config["runner_sha256"] == digest(ROOT / "tools/benchmarks/linux_resume.py")
            and config["reference_helper_sha256"] == current_helpers,
            f"recovery runner provenance drift: {path}")
    require(config["build_profile"] == "release" and config["platform"]["os"] == "Linux"
            and config["platform"]["filesystem"] == "ext4", "unexpected recovery profile")
    count = config["repeats"]
    require(type(count) is int and minimum_trials <= count <= 30, "invalid recovery trial count")

    evidence = report["evidence"]
    fixture = evidence["fixture"]
    require(fixture["logical_bytes"] == fixture["allocated_bytes"] == 128 * (1 << 20)
            and fixture["same_uid_gid_checked"] is True and re.fullmatch(r"[0-9a-f]{64}", fixture["sha256"]),
            "unexpected recovery fixture")
    subjects = {"fresh_copy", "checkpoint_resume"}
    for key in ("verified_samples", "summary", "excluded_warmup"):
        require(set(evidence[key]) == subjects, f"missing recovery subject in {key}")
    for subject in subjects:
        warmup = evidence["excluded_warmup"][subject]
        require(warmup["trial"] == 0, "invalid recovery warm-up ordinal")
        check_recovery_sample(subject, warmup)
        records = evidence["verified_samples"][subject]
        require([item["trial"] for item in records] == list(range(1, count + 1)),
                "invalid recovery trial ordinals")
        samples = [check_recovery_sample(subject, item) for item in records]
        check_samples(samples, evidence["summary"][subject], count)

    control = evidence["trace_control"]
    check_recovery_sample("checkpoint_resume", control, traced=True)
    trace = control["stage_write_control"]
    require(type(trace["writes"]) is int and trace["writes"] > 0
            and trace["first_offset_bytes"] == control["retained_bytes"]
            and trace["payload_bytes_written"] == fixture["logical_bytes"] - control["retained_bytes"]
            and re.fullmatch(r"[0-9a-f]{64}", trace["trace_sha256"]),
            "recovery trace does not demonstrate a suffix-only write")


def check_recovery_sample(subject, sample, *, traced=False):
    require(sample["verified"] is True, f"unverified recovery baseline trial: {subject}")
    assurance = sample["assurance" if subject == "fresh_copy" else "input_copy_assurance"]
    require(assurance["verification"] == "hash_readback"
            and assurance["durability"] == "unconfirmed" and assurance["publication"] == "published"
            and assurance["metadata"] == "complete_for_policy",
            f"recovery baseline copy assurance differs: {subject}")
    if subject == "checkpoint_resume":
        result = sample["timed_report"]
        require(type(sample["retained_bytes"]) is int and 0 < sample["retained_bytes"] <= 64 * (1 << 20)
                and result["schema"] == "exacopy.local_recovery_inspection" and result["schema_version"] == "1.0"
                and result["result"] == "inspected" and result["disposition"] == "complete"
                and result["journal_tail"] == "clean", "checkpoint resume did not confirm completion")
    if traced:
        require("execution" not in sample, "traced execution must stay outside the timed results")
        return None
    execution = sample["execution"]
    require(type(execution["exit_code"]) is int and execution["exit_code"] == 0,
            f"failed recovery baseline trial: {subject}")
    return {key: value for key, value in execution.items() if key != "exit_code"}


def check_performance():
    directory = ROOT / "docs/specs/performance"
    workloads = read_json(directory / "workloads.v1.json")
    require(workloads["schema_version"] == 1, "unknown performance inventory schema")
    require(all(item["status"] == "not_executed" and "evidence" not in item for item in workloads["future"]),
            "future workload has a conflicting evidence status")
    for lane in workloads["baseline"]:
        require(lane["status"] == "executed_pass", f"invalid baseline status: {lane['id']}")
        if lane["id"] == "local-checkpoint-resume":
            check_recovery_performance(directory / lane["evidence"], workloads["budgets"]["minimum_measured_trials"])
            continue
        report = check_evidence(directory / lane["evidence"])
        evidence = report["evidence"]
        count = report["configuration"]["repeats"]
        require(count >= workloads["budgets"]["minimum_measured_trials"], "insufficient measured trials")
        if report["lane"] == "compare":
            require(len(evidence) == 4, "missing comparison cases")
            for case in evidence:
                require(set(case["verified_samples"]) == {"cmp", "exacopy-workers-1", "exacopy-workers-4"},
                        "missing comparison subject")
                for subject, samples in case["verified_samples"].items():
                    check_samples(samples, case["summary"][subject], count)
        else:
            require(report["lane"] == "copy" and len(evidence["workloads"]) == 2, "missing copy cases")
            for case in evidence["workloads"]:
                require(case["assurance"]["verification"] == "hash_readback"
                        and case["assurance"]["durability"] == "unconfirmed", "copy assurance differs")
                check_samples(case["verified_samples"], case["summary"], count)


if __name__ == "__main__":
    require(MACOS_ACL_FIXTURE.is_file(), "shared macOS ACL fixture is missing")
    check_compatibility()
    check_performance()
    print("Reference inventory and performance evidence structure checked")

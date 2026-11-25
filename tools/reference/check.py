#!/usr/bin/env python3
"""Check structural linkage and recorded measurements without rerunning a reference."""

import json
from pathlib import Path
import re

from common import ROOT, digest, require
from run import summarize


REQUIRED_TARGETS = {
    "adb", "beyond-compare-pro", "fastcopy", "freefilesync", "kopia", "openmtp",
    "openssh", "restic", "rsync", "teracopy", "winscp", "wireguard",
}


def read_json(path):
    with path.open() as stream:
        return json.load(stream)


def check_evidence(path):
    report = read_json(path)
    require(report["schema_version"] == 1 and report["outcome"] == "passed", f"ineligible evidence: {path}")
    config = report["configuration"]
    require(re.fullmatch(r"[0-9a-f]{40}", config["source_revision"]) is not None, f"missing revision: {path}")
    for digest_key, file in (("runner_sha256", "run.py"), ("fixture_helper_sha256", "common.py")):
        require(config[digest_key] == digest(ROOT / "tools/reference" / file), f"runner provenance drift: {path}")
    return report


def check_compatibility():
    directory = ROOT / "specs/compatibility"
    inventory = read_json(directory / "inventory.v1.json")
    require(inventory["schema_version"] == 1, "unknown compatibility inventory schema")
    targets = inventory["targets"]
    ids = {target["id"] for target in targets}
    require(len(ids) == len(targets) and REQUIRED_TARGETS.issubset(ids), "missing or duplicate compatibility target")
    for target in targets:
        require(target["primary_sources"], f"missing reference provenance: {target['id']}")
        profiles = target["profiles"]
        require(profiles and len({profile["id"] for profile in profiles}) == len(profiles),
                f"missing or duplicate profiles: {target['id']}")
        for profile in profiles:
            require(profile["acceptance"] and all(re.fullmatch(r"A-\d{3}", id) for id in profile["acceptance"]),
                    f"missing acceptance IDs: {profile['id']}")
            if profile["status"] == "executed_pass":
                report = check_evidence(directory / profile["evidence"])
                evidence = report["evidence"]
                if report["lane"] == "differential":
                    require(len(evidence["cases"]) == 7 and all(case["fixture_preserved"] for case in evidence["cases"]),
                            "differential evidence has missing cases or a changed fixture")
                    require(evidence["symlink_control"]["exa_copy_exit"] == 2, "missing symlink refusal")
                else:
                    require(report["lane"] == "copy" and evidence["incumbent_control"]["source_and_incumbent_preserved"],
                            "missing incumbent-preservation evidence")
            else:
                require(profile["status"] == "not_executed" and profile["evidence"] is None,
                        f"unrecognized status or an unclassified artifact: {profile['id']}")


def check_samples(samples, summary, count):
    require(len(samples) == count, "measured trial count differs")
    require(all(set(sample) == {"elapsed_ns", "user_cpu_ns", "system_cpu_ns", "peak_rss_bytes"}
                and sample["elapsed_ns"] > 0 and sample["peak_rss_bytes"] > 0
                and min(sample.values()) >= 0 for sample in samples), "invalid trial measurements")
    require(summary == summarize(samples), "stored summary differs from the raw trials")


def check_performance():
    directory = ROOT / "specs/performance"
    workloads = read_json(directory / "workloads.v1.json")
    require(workloads["schema_version"] == 1, "unknown performance inventory schema")
    require(all(item["status"] == "not_executed" and "evidence" not in item for item in workloads["future"]),
            "future workload has a conflicting evidence status")
    for lane in workloads["baseline"]:
        require(lane["status"] == "executed_pass", f"invalid baseline status: {lane['id']}")
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
    check_compatibility()
    check_performance()
    print("Reference inventory and performance evidence structure checked")

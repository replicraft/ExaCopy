#!/usr/bin/env python3
"""Run independent local reference checks and verified-operation baselines."""

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import tempfile

from common import (MACOS, build_record, capture, check_diff, diff_command, digest,
                    observation, prepare, require, sample, write_fixture)

MIB = 1 << 20
PROTOCOL = "exacopy-reference-v1"


def fixtures(root, name, left_size, right_size, offset=None, *, sparse=False):
    pair = root / name
    pair.mkdir(mode=0o700)
    left, right = (prepare(pair / side) / "payload" for side in ("left", "right"))
    for path, size, changed_at in ((left, left_size, None), (right, right_size, offset)):
        write_fixture(path, size, name, offset=changed_at, sparse=sparse)
    return left, right


def differential(binary, root, rsync, cmp):
    cases = [
        ("empty-equal", 0, 0, None, False),
        ("binary-equal", 3 * MIB, 3 * MIB, None, False),
        ("first-byte", 3 * MIB, 3 * MIB, 0, False),
        ("middle-byte", 3 * MIB, 3 * MIB, 3 * MIB // 2, False),
        ("final-byte", 3 * MIB, 3 * MIB, 3 * MIB - 1, False),
        ("shorter", 4096, 4095, None, False),
        ("sparse-byte", 6 * MIB, 6 * MIB, 4 * MIB + 17, True),
    ]
    results = []
    for name, left_size, right_size, offset, sparse in cases:
        left, right = fixtures(root, name, left_size, right_size, offset, sparse=sparse)
        before = [observation(path) for path in (left, right)]
        expected_different = left_size != right_size or offset is not None
        cmp_result = sample([cmp, "-s", left, right])
        require(cmp_result["exit_code"] == int(expected_different), f"cmp disagreed with {name}: {cmp_result}")
        rsync_result = sample([rsync, "--dry-run", "--checksum", "--itemize-changes", "--out-format=%i",
                               "--", left, right])
        item = rsync_result["stdout"]
        require(rsync_result["exit_code"] == 0 and not rsync_result["stderr"], f"rsync error: {rsync_result}")
        require((len(item) == 11 and item.startswith(">f")) if expected_different else not item,
                f"rsync disagreed with {name}: {rsync_result}")
        reports = {}
        for workers in (1, 4, 16):
            run = sample(diff_command(binary, left, right, workers))
            reports[str(workers)] = {"exit_code": run["exit_code"], "report": check_diff(run, left_size, right_size, offset)}
        require([observation(path) for path in (left, right)] == before, f"fixture changed: {name}")
        require(all(sorted(p.name for p in path.parent.iterdir()) == [path.name] for path in (left, right)),
                f"fixture namespace changed: {name}")
        results.append({"case": name, "left_bytes": left_size, "right_bytes": right_size, "first_byte": offset,
                        "sparse_fixture": sparse, "allocated_bytes": [p.stat().st_blocks * 512 for p in (left, right)],
                        "sha256": [item["sha256"] for item in before], "cmp_exit": cmp_result["exit_code"],
                        "rsync_exit": rsync_result["exit_code"], "rsync_itemized_change": item,
                        "exa_copy": reports, "fixture_preserved": True})

    left, right = fixtures(root, "symlink-negative-control", 4096, 4096)
    alias = right.parent / "alias"
    alias.symlink_to(right.name)
    cmp_result = sample([cmp, "-s", left, alias])
    run = sample(diff_command(binary, left, alias, 1))
    report = json.loads(run["stdout"])
    require(cmp_result["exit_code"] == 0 and run["exit_code"] == 2 and report["result"] == "inconclusive"
            and report["complete"] is False and report["error"]["code"] == "E_OPEN_INPUT",
            f"symlink control failed: {cmp_result}, {run}")
    require(alias.is_symlink() and alias.readlink() == Path(right.name), "symlink fixture changed")
    return {"cases": results, "symlink_control": {"cmp_exit": 0, "exa_copy_exit": 2, "exa_copy": report}}


def metrics(run):
    return {key: value for key, value in run.items() if key.endswith(("_ns", "_bytes"))}


def summarize(samples):
    return {
        "elapsed_median_ns": int(statistics.median(s["elapsed_ns"] for s in samples)),
        "elapsed_min_ns": min(s["elapsed_ns"] for s in samples),
        "elapsed_max_ns": max(s["elapsed_ns"] for s in samples),
        "cpu_median_ns": int(statistics.median(s["user_cpu_ns"] + s["system_cpu_ns"] for s in samples)),
        "peak_rss_bytes": max(s["peak_rss_bytes"] for s in samples),
    }


def compare_benchmark(binary, root, cmp, repeats):
    cases = [("small-equal", 4096, None), ("large-equal", 64 * MIB, None),
             ("large-early-difference", 64 * MIB, 0), ("large-late-difference", 64 * MIB, 64 * MIB - 1)]
    results = []
    for name, size, offset in cases:
        left, right = fixtures(root, name, size, size, offset)
        before = [observation(path) for path in (left, right)]
        commands = {"cmp": [cmp, "-s", left, right],
                    **{f"exacopy-workers-{n}": diff_command(binary, left, right, n) for n in (1, 4)}}
        samples = {name: [] for name in commands}
        for trial in range(repeats + 1):
            ordering = list(commands)
            shift = trial % len(ordering)
            for subject in ordering[shift:] + ordering[:shift]:
                run = sample(commands[subject])
                if subject == "cmp":
                    require(run["exit_code"] == int(offset is not None), f"cmp benchmark failed: {run}")
                else:
                    check_diff(run, size, size, offset)
                if trial:
                    samples[subject].append(metrics(run))
        require([observation(path) for path in (left, right)] == before, f"fixture changed: {name}")
        results.append({"case": name, "bytes_per_file": size, "first_byte": offset,
                        "verified_samples": samples, "summary": {k: summarize(v) for k, v in samples.items()}})
    return results


def copy_command(binary, source, target, profile):
    return [binary, "copy", source, target, "--profile", profile, "--format", "json"]


def check_copy(binary, run, profile, source, target, before, cmp):
    require(run["exit_code"] == 0, f"copy failed: {run}")
    report = json.loads(run["stdout"])
    expected = {"schema": "exacopy.cli.copy", "schema_version": "1.0", "publication": "published",
                "completed": 1, "pending": 0, "verification": "hash_readback", "consistency": "live_observed",
                "durability": "unconfirmed", "preservation": "preserve", "redundancy": "independent_writes",
                "metadata": "complete_for_policy"}
    require(all(report[key] == value for key, value in expected.items()), f"incorrect copy report: {report}")
    receipt = report["receipt"]
    require(receipt["length"] == str(before["length"]) and len(receipt["receipt_digest"]) == 64,
            f"missing committed evidence: {receipt}")
    after = observation(target)
    require(before["identity"] != after["identity"] and before["links"] == after["links"] == 1,
            "target must be independently written")
    for field in ("mode", "mtime_ns", "length", "sha256"):
        require(before[field] == after[field], f"target {field} differs")
    require(sample([cmp, "-s", source, target])["exit_code"] == 0, "independent published byte check failed")
    require(observation(source) == before, "source changed")
    job = target.parent / receipt["job_directory"]
    require(job.parent == target.parent and job.name == f".exacopy-{receipt['job_id']}", "invalid job binding")
    inspection = sample([binary, "recover", "inspect", job, "--profile", profile, "--format", "json"])
    require(inspection["exit_code"] == 0 and json.loads(inspection["stdout"])["disposition"] == "complete",
            f"committed state failed inspection: {inspection}")
    return expected


def copy_benchmark(binary, root, rsync, cmp, repeats):
    profile = root / "profile"
    initialized = sample([binary, "profile", "init", profile])
    require(initialized["exit_code"] == 0, f"profile initialization failed: {initialized}")
    results = []
    for name, size in [("small-copy", 4096), ("large-copy", 64 * MIB)]:
        case = prepare(root / name)
        source = prepare(case / "source") / "file"
        write_fixture(source, size, name)
        before = observation(source)
        samples = []
        for trial in range(repeats + 1):
            target = prepare(case / f"trial-{trial}") / "file"
            require(not target.exists(), "benchmark requires an absent destination")
            run = sample(copy_command(binary, source, target, profile))
            assurance = check_copy(binary, run, profile, source, target, before, cmp)
            if trial:
                samples.append(metrics(run))
        results.append({"case": name, "bytes": size, "assurance": assurance, "sha256": before["sha256"],
                        "verified_samples": samples, "summary": summarize(samples)})

    controls = prepare(root / "incumbent-control")
    source = prepare(controls / "source") / "file"
    incumbent = prepare(controls / "incumbent") / "file"
    write_fixture(source, 4096, "source")
    write_fixture(incumbent, 4096, "incumbent")
    before = [observation(path) for path in (source, incumbent)]
    reference = sample([rsync, "--ignore-existing", "--itemize-changes", "--out-format=%i", "--", source, incumbent])
    require(reference["exit_code"] == 0 and not reference["stdout"] and not reference["stderr"], f"rsync did not skip: {reference}")
    require([observation(path) for path in (source, incumbent)] == before, "rsync changed protected content")
    reference_target = prepare(controls / "reference") / "file"
    reference_copy = sample([rsync, "--ignore-existing", "--itemize-changes", "--out-format=%i", "--", source, reference_target])
    require(reference_copy["exit_code"] == 0 and not reference_copy["stderr"]
            and sample([cmp, "-s", source, reference_target])["exit_code"] == 0,
            f"rsync copy failed oracle: {reference_copy}")
    require(observation(source) == before[0], "rsync mutated its source")
    run = sample(copy_command(binary, source, incumbent, profile))
    report = json.loads(run["stdout"])
    require(run["exit_code"] == 3 and report["completed"] == 0 and report["publication"] == "not_published"
            and report["error"]["code"] == "E_CONFLICT", f"incumbent control failed: {run}")
    require([observation(path) for path in (source, incumbent)] == before, "copy changed protected content")
    return {"workloads": results, "rsync_copy": {"reference_exit": 0, "cmp_exit": 0, "item": reference_copy["stdout"]},
            "incumbent_control": {"exacopy_exit": 3, "exacopy_error": "E_CONFLICT", "rsync_exit": 0,
                                  "rsync_itemized_change": reference["stdout"], "source_and_incumbent_preserved": True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("differential", "compare", "copy"))
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--source-revision", help="exact archived source commit, when building without repository metadata")
    parser.add_argument("--scratch-parent", required=True, type=Path, help="trusted native filesystem for fresh synthetic fixtures")
    parser.add_argument("--build-profile", choices=("dev", "release"), default="release")
    parser.add_argument("--hardware", required=True, help="CPU, RAM, storage and virtualization/topology, with identifiers omitted")
    parser.add_argument("--output", required=True, type=Path, help="path to a new result JSON file")
    parser.add_argument("--repeats", type=int, default=9)
    arguments = parser.parse_args()
    require(5 <= arguments.repeats <= 30, "use 5 through 30 repetitions")
    require(arguments.kind != "copy" or not MACOS, "copy baseline requires the Linux CLI")
    binary = arguments.binary.resolve(strict=True)
    rsync = shutil.which("rsync") if arguments.kind in ("copy", "differential") else None
    cmp = shutil.which("cmp")
    require(cmp and (rsync or arguments.kind == "compare"), "install system cmp and rsync for the requested lane")
    with tempfile.TemporaryDirectory(prefix="exacopy-reference-", dir=arguments.scratch_parent.resolve(strict=True)) as directory:
        root = Path(directory)
        try:
            cmp_version = capture(["what", cmp]) if MACOS else capture([cmp, "--version"]).splitlines()[0]
            metadata = build_record(binary, arguments.source_revision, arguments.build_profile, root)
            metadata.update({"hardware": arguments.hardware, "cmp_version": cmp_version,
                             "cmp_sha256": digest(Path(cmp)), "runner_sha256": digest(Path(__file__)),
                             "fixture_helper_sha256": digest(Path(__file__).with_name("common.py")),
                             "cache": "warm: fresh fixtures, read before trials; one warm-up excluded",
                             "repeats": arguments.repeats})
            if rsync:
                metadata["rsync_version"] = capture([rsync, "--version"]).splitlines()[0]
                metadata["rsync_sha256"] = digest(Path(rsync))
            if arguments.kind == "differential":
                evidence = differential(binary, root, rsync, cmp)
            elif arguments.kind == "compare":
                evidence = compare_benchmark(binary, root, cmp, arguments.repeats)
            else:
                evidence = copy_benchmark(binary, root, rsync, cmp, arguments.repeats)
            report = {"schema_version": 1, "protocol": PROTOCOL, "lane": arguments.kind,
                      "outcome": "passed", "configuration": metadata, "evidence": evidence}
        except Exception as error:
            report = {"schema_version": 1, "protocol": PROTOCOL, "lane": arguments.kind,
                      "outcome": "failed", "reason": str(error)}
            with arguments.output.open("x") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
            raise
    with arguments.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()

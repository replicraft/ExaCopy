"""Contribute separately admitted native cohorts to the ordinary LLVM campaign."""

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess

import ordinary_coverage_cohorts as cohorts
import ordinary_coverage_image as image_selection
import run

ext4 = run.ext4
profiles_api = run.coverage_profile
require = ext4.require
WORKFLOW = "replicraft/ExaCopy/.github/workflows/coverage.yml@refs/heads/main"
ORDINARY = "endpoint-coverage-ordinary.json"
COMBINED = "endpoint-coverage.json"


def admission():
    revision = os.environ["GITHUB_SHA"]
    run.check_coverage_host(revision)
    require(os.environ.get("GITHUB_WORKFLOW_REF") == WORKFLOW
            and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
            and os.environ.get("GITHUB_JOB") == "coverage",
            "ordinary witness coverage requires the exact canonical Coverage workflow")
    run_id, attempt = (os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run_id, attempt)),
            "missing ordinary coverage run identity")
    require(not any(os.environ.get(key) for key in run.COMPILER_OVERRIDES)
            and not os.environ.get("LLVM_PROFILE_FILE"),
            "compiler, loader or profile override present before ordinary coverage")
    temp = Path(os.environ["RUNNER_TEMP"])
    require(temp.is_absolute() and temp.resolve(strict=True) == temp, "invalid RUNNER_TEMP")
    return temp, {"revision": revision, "workflow": WORKFLOW, "run": run_id, "attempt": attempt}


def snapshot(context, evidence, phase):
    state = image_selection.source_snapshot(context["revision"], evidence, phase)
    source = Path(__file__).relative_to(run.ROOT)
    driver_sha256 = hashlib.sha256((run.ROOT / source).read_bytes()).hexdigest()
    return {"context": context, "source": {"image": state, "driver_sha256": driver_sha256}}


def private_parent(path):
    metadata = path.stat(follow_symlinks=False)
    require(path.resolve(strict=True) == path and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022,
            "ordinary coverage evidence parent is not private")


def prepare(context, evidence):
    private_parent(evidence.parent)
    require(all(not os.path.lexists(evidence.parent / name) for name in (ORDINARY, COMBINED)),
            "ordinary witness coverage requires a fresh campaign")
    capture = evidence.parent / "endpoint-llvm-export"
    private_parent(capture)
    require(stat.S_IMODE(capture.stat().st_mode) == 0o700 and not list(capture.iterdir()),
            "ordinary LLVM capture slot is not fresh and private")
    evidence.mkdir(mode=0o700)
    with (evidence / "before-build.json").open("x") as output:
        selection = snapshot(context, evidence, "ordinary-prebuild")
        selection["tools"] = prebuild_tools(evidence)
        json.dump(selection, output, sort_keys=True)
        output.write("\n")


def bind_file(stack, path, limit, *, expected=None, private_copy=False):
    fd = os.open(path, ext4.FD_FLAGS | os.O_NONBLOCK)
    stack.callback(os.close, fd)
    node = os.fstat(fd)
    original = profiles_api.stamp(node)
    require(stat.S_ISREG(node.st_mode) and not node.st_mode & 0o022
            and 0 < node.st_size <= limit, "ordinary LLVM input is not a bounded regular file")

    if private_copy:
        require(node.st_nlink == 1 and node.st_uid == os.geteuid(),
                "retained native profile must be owned and singly named")

    def verify():
        digest = hashlib.sha256()
        offset = 0
        while offset < node.st_size:
            block = os.pread(fd, min(1024 * 1024, node.st_size - offset), offset)
            require(block, "ordinary LLVM input ended early")
            digest.update(block)
            offset += len(block)
        require(not os.pread(fd, 1, offset) and profiles_api.stamp(os.fstat(fd)) == original
                and profiles_api.stamp(path.stat(follow_symlinks=False)) == original,
                "ordinary LLVM input changed")
        return {"path": str(path), "size": offset, "sha256": digest.hexdigest()}

    receipt = verify()
    if expected is not None:
        require(all(receipt[key] == expected[key] for key in ("sha256", "size")),
                "ordinary LLVM bytes differ from their capture")
    return fd, receipt, lambda: require(verify() == receipt, "ordinary LLVM input digest changed")



def prebuild_tools(evidence):
    directory = evidence / "prebuild-tools"
    directory.mkdir(mode=0o700)
    compiler = ext4.command(directory, "rustc", ["rustc", f"+{run.TOOLCHAIN}", "-vV"]).splitlines()
    require(f"release: {run.TOOLCHAIN}" in compiler and f"host: {run.TARGET}" in compiler,
            "unexpected ordinary coverage compiler before build")
    paths = profiles_api.pinned_tools(ext4, directory, compiler, {})
    with ExitStack() as stack:
        return {name: bind_file(stack, path, profiles_api.IMAGE_LIMIT)[1]
                for name, path in paths.items()}


def file_rows(raw):
    exported = profiles_api.parse_export(raw)
    require(exported.get("type") == profiles_api.EXPORT_TYPE
            and exported.get("version") == profiles_api.EXPORT_VERSION
            and len(exported.get("data", [])) == 1, "invalid ordinary LLVM report")
    rows = {}
    for item in exported["data"][0]["files"]:
        name = item["filename"]
        require(type(name) is str and name and name not in rows, "duplicate or invalid LLVM file row")
        counts = item["summary"]["lines"]
        counted, covered = counts["count"], counts["covered"]
        require(type(counted) is int and type(covered) is int and 0 <= covered <= counted,
                "invalid ordinary LLVM line counters")
        rows[name] = counted, covered
    require(rows, "ordinary LLVM file inventory is empty")
    return rows


def same_denominator(before, after):
    require(before.keys() == after.keys()
            and all(total == after[name][0] and covered <= after[name][1]
                    for name, (total, covered) in before.items()),
            "combined LLVM export changed the ordinary file set, denominator or baseline counts")



def admitted_runs(coverage, cases, executable_sha256):
    measured = coverage["admitted_profiles"]
    discarded = coverage["discarded_listing_profiles"]
    expected_runs = [(f"case-{i}-run", case) for i, case in enumerate(cases, 1)]
    expected_listings = [(f"case-{i}-{kind}", case) for i, case in enumerate(cases, 1)
                         for kind in ("listed", "ignored")]
    require([(p["launch"], p["selector"]) for p in measured] == expected_runs
            and [(p["launch"], p["selector"]) for p in discarded] == expected_listings
            and all(p["retained"] == f'{p["launch"]}.profraw' for p in measured)
            and all("retained" not in p for p in discarded)
            and all(p["executable_sha256"] == executable_sha256 for p in (*measured, *discarded)),
            "ordinary witness profile attendance differs")
    return measured


def admitted_cohorts(reports, executable_sha256):
    require([report["id"] for report in reports] == [name for name, _ in cohorts.COHORTS],
            "ordinary native cohort inventory differs")
    admitted = []
    discarded = 0
    for report, (name, cases) in zip(reports, cohorts.COHORTS, strict=True):
        require(report["outcome"] == "pass" and report["cleanup"] == "verified_absent"
                and report["executable_sha256"] == executable_sha256
                and report["cases"] == dict.fromkeys(cases, "pass"),
                "ordinary native cohort lacks exact tests, executable or cleanup")
        coverage = report["coverage"]
        admitted.append((name, admitted_runs(coverage, cases, executable_sha256)))
        discarded += len(coverage["discarded_listing_profiles"])
    require(sum(len(profiles) for _, profiles in admitted) == 17 and discarded == 34,
            "ordinary native cohort profile totals differ")
    return admitted


def execute_cases(evidence, fixture, fixture_fd, profiles, selected, cases, report):
    path, fd, original = selected
    report["executable_sha256"] = original[1]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(fixture)}
    for index, case in enumerate(cases, 1):
        label = f"case-{index}-run"
        require(not os.listdir(fixture_fd), "ordinary witness fixture occupied")
        try:
            output = ext4.command(evidence, label, [path, "--ignored", "--exact", "--test-threads=1",
                                  "--color", "never", case], env=profiles.allocate(label, env),
                                  executable=profiles_api.fd_path(fd), held=(fd,), timeout=45)
        finally:
            require(ext4.held_managed_image(path, fd) == original and not os.listdir(fixture_fd),
                    "ordinary witness held executable or fixture changed")
        run.check_test(output, case)
        profiles.collect(label, case, original[1])
        report["cases"][case] = "pass"


def held_tool(evidence, label, tool, args, inputs, *, output_limit=65536):
    executable, receipt, verify = tool
    verify()
    output = ext4.command(evidence, label, [receipt["path"], *args], env=profiles_api.TOOL_ENV,
                          executable=profiles_api.fd_path(executable), held=(executable, *inputs),
                          output_limit=output_limit, timeout=90)
    verify()
    require(not (evidence / f"{label}.stderr").stat().st_size, f"{label} reported LLVM diagnostics")
    return output


def execute_cohort(name, cases, temp, context, source, evidence, selected, check_inputs, report):
    def run_ordinary(fixture, fixture_fd, profiles, tools):
        check_inputs(tools)
        require(snapshot(context, evidence, "cohort-before") == source,
                "ordinary coverage source changed before cohort listing")
        if name == cohorts.PROTECTED_SNAPSHOT:
            report["snapshot_substrate"] = cohorts.snapshot_substrate(
                fixture, fixture_fd, evidence, "snapshot-before")
            cohorts.check_snapshot_acl(fixture)
            report["posix_acl"] = "verified_masked_access_acl"
        image_selection.list_cases(evidence, fixture, fixture_fd, profiles, selected, cases)
        require(snapshot(context, evidence, "cohort-listed") == source,
                "ordinary coverage source changed during cohort listing")
        execute_cases(evidence, fixture, fixture_fd, profiles, selected, cases, report)
        if name == cohorts.PROTECTED_SNAPSHOT:
            require(cohorts.snapshot_substrate(fixture, fixture_fd, evidence, "snapshot-after")
                    == report["snapshot_substrate"], "protected snapshot fixture substrate changed")
        check_inputs(tools)

    try:
        run.qualify(context["revision"], temp, evidence, report, ordinary=run_ordinary)
    except ext4.Blocked:
        report["outcome"] = "blocked"
        raise
    report["outcome"] = "pass"


def combine(temp, context, evidence, report):
    private_parent(evidence)
    require(stat.S_IMODE(evidence.stat().st_mode) == 0o700, "ordinary witness evidence is not private")
    collector_spec = importlib.util.spec_from_file_location("ordinary_endpoint_capture", image_selection.COLLECTOR)
    collector = importlib.util.module_from_spec(collector_spec)
    collector_spec.loader.exec_module(collector)
    target = run.ROOT / "target/llvm-cov-target"
    export_dir = evidence.parent / "endpoint-llvm-export"
    with ExitStack() as stack, image_selection.held_capture_pair(export_dir) as read_pair:
        before_fd, _, check_before = bind_file(stack, evidence / "before-build.json", image_selection.CAPTURE_LIMIT)
        before = json.loads(os.pread(before_fd, image_selection.CAPTURE_LIMIT, 0))
        require(before["context"] == context, "prebuild source belongs to a different coverage run")
        producer_fd, producer, check_producer = bind_file(stack, evidence / "ordinary-producer.exit", 16)
        require(os.pread(producer_fd, 16, 0) == b"0\n", "ordinary coverage producer did not complete")
        ordinary_fd, ordinary_report, check_report = bind_file(
            stack, evidence.parent / ORDINARY, profiles_api.EXPORT_LIMIT)
        ordinary_rows = file_rows(os.pread(ordinary_fd, profiles_api.EXPORT_LIMIT, 0))
        raw = read_pair()
        recorded = profiles_api.parse_export(raw)
        report.update(source=before["source"], prebuild_tools=before["tools"],
                      ordinary_report=ordinary_report, ordinary_producer=producer,
                      capture_sha256=hashlib.sha256(raw).hexdigest())
        expected_snapshot = {key: before[key] for key in ("context", "source")}
        exporter = Path(before["tools"]["llvm-cov"]["path"])
        selected_object = image_selection.verify_capture(collector, raw, exporter, target)
        inputs = {
            name: bind_file(stack, Path(before["tools"][key]["path"]), collector.FILE_LIMIT,
                            expected=before["tools"][key])
            for name, key in (("cov", "llvm-cov"), ("profdata", "llvm-profdata"))
        }
        require(inputs["cov"][1] == before["tools"]["llvm-cov"] == recorded["tool"]
                and inputs["profdata"][1] == before["tools"]["llvm-profdata"],
                "ordinary LLVM tools differ from prebuild capture")
        inputs["ordinary"] = bind_file(stack, Path(recorded["indexed_profile"]["path"]),
                                       profiles_api.INDEXED_PROFILE_LIMIT,
                                       expected=recorded["indexed_profile"])
        inputs["objects"] = [
            bind_file(stack, Path(item["path"]), collector.FILE_LIMIT, expected=item)
            for item in recorded["objects"]
        ]
        selected_fd, = (entry[0] for entry in inputs["objects"] if entry[1]["path"] == selected_object["path"])
        selected_path = Path(selected_object["path"])
        held_image = ext4.held_managed_image(selected_path, selected_fd)
        require((held_image[0][6], held_image[1]) == (selected_object["size"], selected_object["sha256"]),
                "held ordinary platform ELF differs from capture")
        selected = selected_path, selected_fd, held_image
        report["executable_sha256"] = held_image[1]
        report["executable"] = {**selected_object, "held_stamp": list(held_image[0])}

        def check_inputs(tools):
            require(str(tools["llvm-cov"]) == inputs["cov"][1]["path"]
                    and str(tools["llvm-profdata"]) == inputs["profdata"][1]["path"],
                    "native cohort tool selection differs from the held ordinary tools")
            inputs["cov"][2]()
            inputs["profdata"][2]()
            cohorts.check_unprivileged_image(selected_fd)
            report["executable"]["file_capabilities"] = "absent"
            require(read_pair() == raw and ext4.held_managed_image(selected_path, selected_fd) == held_image
                    and not ext4.supervision.CANCELLATION_REQUESTED,
                    "ordinary campaign changed during native cohort")

        cohort_root = evidence / "cohorts"
        cohort_root.mkdir(mode=0o700)
        for name, cases in cohorts.COHORTS:
            cohort_evidence = cohort_root / name
            cohort_evidence.mkdir(mode=0o700)
            result = {"id": name, "outcome": "failed", "cleanup": "not_created",
                      "cases": {}, "coverage": {}}
            report["cohorts"].append(result)
            execute_cohort(name, cases, temp, context, expected_snapshot, cohort_evidence,
                           selected, check_inputs, result)

        admitted = admitted_cohorts(report["cohorts"], held_image[1])
        require(all(result["substrate"] == report["cohorts"][0]["substrate"] for result in report["cohorts"]),
                "ordinary native cohorts used different runner substrates")
        report["cleanup"] = "verified_absent"
        raw_inputs = []
        for name, entries in admitted:
            cohort_evidence = cohort_root / name
            require({path.name for path in cohort_evidence.glob("*.profraw")}
                    == {profile["retained"] for profile in entries},
                    "retained native profile file inventory differs")
            raw_inputs.extend(bind_file(stack, cohort_evidence / profile["retained"], profiles_api.RAW_LIMIT,
                                        expected=profile, private_copy=True) for profile in entries)
        retained_nodes = [os.fstat(profile[0]) for profile in raw_inputs]
        require(len({(node.st_dev, node.st_ino) for node in retained_nodes}) == 17,
                "duplicate retained native profile identity")

        object_fds = tuple(item[0] for item in inputs["objects"])
        argv = recorded["argv"]

        def export(label, profile):
            args = [*argv[:2], f"-instr-profile={profiles_api.fd_path(profile)}"]
            for fd in object_fds:
                args.extend(("-object", profiles_api.fd_path(fd)))
            args.extend(argv[3 + 2 * len(object_fds):])
            return held_tool(evidence, label, inputs["cov"], args, (profile, *object_fds),
                             output_limit=profiles_api.EXPORT_LIMIT)

        original = inputs["ordinary"][0]
        require(file_rows(export("ordinary-reexport", original)) == ordinary_rows,
                "ordinary report does not match the captured indexed profile and objects")
        merged = evidence / "merged.profdata"
        require(not os.path.lexists(merged), "ordinary witness merge slot already exists")
        merge_fds = (original, *(profile[0] for profile in raw_inputs))
        held_tool(evidence, "ordinary-witness-merge", inputs["profdata"],
                  ["merge", "--failure-mode=any", "--sparse", "-o", merged,
                   *(profiles_api.fd_path(fd) for fd in merge_fds)], merge_fds)
        merged_fd, merged_receipt, check_merged = bind_file(stack, merged, profiles_api.INDEXED_PROFILE_LIMIT)
        output = export("ordinary-witness-export", merged_fd)
        same_denominator(ordinary_rows, file_rows(output))
        report["merge"] = {"indexed_input": inputs["ordinary"][1], "indexed_output": merged_receipt,
                           "raw_profiles": [profile[1] for profile in raw_inputs]}
        report["objects"] = recorded["objects"]
        report["ignore_filename_regex"] = recorded["ignore_filename_regex"]
        report["tool"] = {name: inputs[name][1] for name in ("cov", "profdata")}
        for bound in (inputs["cov"], inputs["profdata"], inputs["ordinary"], *inputs["objects"], *raw_inputs):
            bound[2]()
        check_merged()
        check_before()
        check_producer()
        check_report()
        cohorts.check_unprivileged_image(selected_fd)
        require(read_pair() == raw and snapshot(context, evidence, "ordinary-final") == expected_snapshot
                and not ext4.supervision.CANCELLATION_REQUESTED, "ordinary campaign changed before export admission")
        export_path = evidence / "ordinary-witness-export.stdout"
        encoded = output.encode("utf-8")
        bind_file(stack, export_path, profiles_api.EXPORT_LIMIT,
                  expected={"size": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()})
        os.link(export_path, evidence / "combined-llvm.json", follow_symlinks=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "combine"))
    args = parser.parse_args()
    temp, context = admission()
    evidence = temp / "exacopy-evidence/endpoint-ordinary-witness"
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, ext4.supervision.interrupted)
    if args.phase == "prepare":
        prepare(context, evidence)
        return 0
    report = {"schema_version": 2, "context": context, "scope": "ordinary-native-cohort-coverage",
              "revision": context["revision"], "outcome": "failed", "cleanup": "pending", "cohorts": []}
    code = 1
    try:
        combine(temp, context, evidence, report)
    except ext4.Blocked as error:
        report.update(outcome="blocked", reason=str(error))
        code = 77
    except (KeyError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
    else:
        report["outcome"] = "pass"
        code = 0
    finally:
        with (evidence / "result.json").open("x") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())

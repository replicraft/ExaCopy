#!/usr/bin/env python3
"""Measure local checkpointed resume and fresh verified copy on Linux ext4."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference"))
import common
import run as reference


MIB = 1 << 20
SIZE = 128 * MIB
SEED = "linux-resume-128m"
JOURNAL = "journal/00000000000000000001.exajnl"
RECEIPT = "receipts/receipt.cbor"
STAGE = "stage/data"
FIRST_PAGE = "checkpoints/range-0000000001.cbor"
FRAME_HEADER = struct.Struct("<8sHHIQ32s")
FRAME_TRAILER_BYTES = 36
STAGE_WRITE = re.compile(r"^pwrite64\(\d+<[^>]+/stage/data>, .*?, (\d+), (\d+)\) += (\d+)$")


def recovery(binary, action, job, profile, source_root=None):
    command = [binary, "recover", action, job, "--profile", profile, "--format", "json"]
    if source_root is not None:
        command.extend(["--source-root", source_root])
    return command


def check_recovery(run, disposition, exit_code=0):
    common.require(run["exit_code"] == exit_code and not run["stderr"], f"recovery result: {run}")
    report = json.loads(run["stdout"])
    common.require(report["schema"] == "exacopy.local_recovery_inspection"
                   and report["schema_version"] == "1.0" and report["result"] == "inspected"
                   and report["journal_tail"] == "clean" and report["disposition"] == disposition,
                   f"recovery report: {report}")
    return report


def first_checkpoint(prefix, page):
    """Read only the v1 fixture's first frame boundary and range length."""
    offset = 0
    for kind in (1, 2, 3):
        magic, version, record_kind, length, sequence, _ = FRAME_HEADER.unpack_from(prefix, offset)
        common.require((magic, version, record_kind, sequence) == (b"EXAJNL01", 1, kind, kind)
                       and length <= MIB, "unexpected v1 fixture journal frame")
        offset += FRAME_HEADER.size + length + FRAME_TRAILER_BYTES
    common.require(offset <= len(prefix), "incomplete checkpoint frame")
    # Deterministic CBOR map header, followed by version 1, ordinal 1, stream 0 and offset 0.
    page_prefix = b"\xa7\x00\x01\x01\x01\x02\x00\x03\x00\x04"
    common.require(page.startswith(page_prefix), "unexpected v1 first range page")
    tag = page[len(page_prefix)]
    common.require(tag <= 26, "unexpected CBOR range-length format")
    width = {24: 1, 25: 2, 26: 4}.get(tag, 0)
    tail = len(page_prefix) + 1 + width
    length = int.from_bytes(page[tail - width:tail], "big") if width else tag
    common.require(0 < length <= 64 * MIB and len(page[tail:]) == 70, "invalid first range length")
    return prefix[:offset], length


def check_traced_writes(trace, retained):
    current = retained
    operations = 0
    for line in trace.read_text().splitlines():
        if "/stage/data>" not in line:
            continue
        match = STAGE_WRITE.fullmatch(line)
        common.require(match is not None, f"unexpected stage syscall: {line}")
        count, offset, result = map(int, match.groups())
        common.require(count == result > 0 and offset == current, f"noncontiguous stage write: {line}")
        current += result
        operations += 1
    common.require(current == SIZE, f"trace ended at {current}, expected {SIZE}")
    return {"writes": operations, "first_offset_bytes": retained, "payload_bytes_written": current - retained,
            "trace_sha256": common.digest(trace)}


def fixture_metadata(path):
    metadata = path.stat()
    return {"uid": metadata.st_uid, "gid": metadata.st_gid, "atime_ns": metadata.st_atime_ns,
            "mtime_ns": metadata.st_mtime_ns, "mode": metadata.st_mode}


def resumed(binary, source, target, profile, before, cmp, observed, strace=None):
    expected_metadata = fixture_metadata(source)
    setup = common.sample(reference.copy_command(binary, source, target, profile))
    common.require(fixture_metadata(target) == expected_metadata, "setup target metadata differs")
    assurance = reference.check_copy(binary, setup, profile, source, target, before, cmp)
    job = target.parent / json.loads(setup["stdout"])["receipt"]["job_directory"]
    journal = job / JOURNAL
    page = job / FIRST_PAGE
    stage = job / STAGE
    receipt = job / RECEIPT
    accepted_page = page.read_bytes()
    prefix, retained = first_checkpoint(journal.read_bytes(), accepted_page)
    observed["retained_bytes"] = retained

    # The input is an owned synthetic image reconstructed from an authentic completed copy.
    target.rename(stage)
    with stage.open("r+b") as stream:
        stream.truncate(retained)
    with journal.open("r+b") as stream:
        stream.truncate(len(prefix))
    receipt.unlink()
    retained_inode = stage.stat().st_ino
    common.require(not target.exists() and stage.stat().st_size == retained, "invalid retained fixture")

    command = recovery(binary, "resume", job, profile, source.parent)
    trace = target.parent / "write.trace"
    if strace is not None:
        command = [strace, "-y", "-s", "0", "-o", trace, "-e",
                   "trace=pwrite64,pwritev,pwritev2,write,writev", "--", *command]
    timed = common.sample(command)
    observed["execution"] = {"exit_code": timed["exit_code"], **reference.metrics(timed)}
    report = check_recovery(timed, "complete")
    observed["timed_report"] = report
    committed = journal.read_bytes()
    common.require(committed.startswith(prefix) and len(committed) > len(prefix)
                   and len(committed) == int(report["journal_offset"]) and page.read_bytes() == accepted_page,
                   "checkpoint evidence changed or commit missing")
    common.require(fixture_metadata(target) == expected_metadata, "recovered target metadata differs")
    final = common.observation(target)
    common.require(final["identity"] == (before["identity"][0], retained_inode)
                   and final["identity"] != before["identity"] and final["links"] == 1 and not stage.exists(),
                   "published target must be the retained stage")
    for field in ("mode", "mtime_ns", "length", "sha256"):
        common.require(final[field] == before[field], f"recovered target {field} differs")
    common.require(common.sample([cmp, "-s", source, target])["exit_code"] == 0,
                   "independent recovered byte check failed")
    inspection = common.sample(recovery(binary, "inspect", job, profile))
    common.require(check_recovery(inspection, "complete") == report, "committed state changed")
    receipt_before = receipt.read_bytes()
    replay = common.sample(recovery(binary, "resume", job, profile, source.parent))
    common.require(check_recovery(replay, "complete") == report and receipt_before
                   and receipt.read_bytes() == receipt_before and journal.read_bytes() == committed
                   and common.observation(target) == final and common.observation(source) == before,
                   "repeated resume changed committed evidence, target, or source")
    observed["verified"] = True
    observed["input_copy_assurance"] = assurance
    if strace is not None:
        observed["stage_write_control"] = check_traced_writes(trace, retained)
        del observed["execution"]  # Tracing perturbs wall time and process resource counters.


def measure(binary, root, cmp, strace, repeats, result):
    profile = root / "profile"
    initialized = common.sample([binary, "profile", "init", profile])
    common.require(initialized["exit_code"] == 0, f"profile initialization failed: {initialized}")
    source = common.prepare(root / "source") / "payload"
    common.write_fixture(source, SIZE, SEED)
    before = common.observation(source)
    source_metadata = fixture_metadata(source)
    result["fixture"] = {"logical_bytes": SIZE, "allocated_bytes": source.stat().st_blocks * 512,
                         "mode": "0600", "mtime_ns": before["mtime_ns"], "atime_ns": source_metadata["atime_ns"],
                         "same_uid_gid_checked": True, "sha256": before["sha256"],
                         "seed": SEED, "generator": "exacopy-reference-v1 bounded SHAKE-256 blocks"}
    samples = {"fresh_copy": [], "checkpoint_resume": []}
    result["verified_samples"] = samples
    result["excluded_warmup"] = {}
    for trial in range(repeats + 1):
        order = ("fresh_copy", "checkpoint_resume")
        for subject in (order if trial % 2 == 0 else order[::-1]):
            records = samples[subject] if trial else None
            observed = {"trial": trial}
            if records is None:
                result["excluded_warmup"][subject] = observed
            else:
                records.append(observed)
            with tempfile.TemporaryDirectory(prefix=f"{subject}-", dir=root) as directory:
                target = Path(directory) / "payload"
                if subject == "checkpoint_resume":
                    resumed(binary, source, target, profile, before, cmp, observed)
                else:
                    timed = common.sample(reference.copy_command(binary, source, target, profile))
                    observed["execution"] = {"exit_code": timed["exit_code"], **reference.metrics(timed)}
                    common.require(timed["exit_code"] == 0 and fixture_metadata(target) == source_metadata,
                                   f"fresh copy result or target metadata differs: {timed}")
                    observed["assurance"] = reference.check_copy(binary, timed, profile, source, target, before, cmp)
                    observed["verified"] = True
    result["summary"] = {subject: reference.summarize([item["execution"] for item in records])
                         for subject, records in samples.items()}
    result["trace_control"] = {}
    with tempfile.TemporaryDirectory(prefix="resume-trace-", dir=root) as directory:
        resumed(binary, source, Path(directory) / "payload", profile, before, cmp, result["trace_control"], strace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--source-revision", help="exact archived source commit")
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--hardware", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=9)
    args = parser.parse_args()
    common.require(platform.system() == "Linux", "Linux is required")
    common.require(5 <= args.repeats <= 30, "use 5 through 30 repetitions")
    binary = args.binary.resolve(strict=True)
    cmp = shutil.which("cmp")
    strace = shutil.which("strace")
    common.require(cmp and strace, "install GNU cmp and strace")
    report = {"schema_version": 1, "protocol": "exacopy-linux-resume-v1",
              "started_utc": datetime.now(timezone.utc).isoformat(), "evidence": {}}
    with args.output.open("x") as output:
        try:
            with tempfile.TemporaryDirectory(prefix="exacopy-resume-", dir=args.scratch_parent) as directory:
                root = Path(directory)
                metadata = common.build_record(binary, args.source_revision, "release", root)
                report["configuration"] = metadata
                common.require(metadata["platform"]["filesystem"] == "ext4", "fixture volume must be ext4")
                metadata.update({
                    "build_command": "cargo build --locked --release -p exacopy-cli",
                    "hardware": args.hardware,
                    "guest_online_cpus": common.capture(["getconf", "_NPROCESSORS_ONLN"]),
                    "guest_mem_total": Path("/proc/meminfo").read_text().splitlines()[0],
                    "mount": common.capture(["findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS", "--target", root]),
                    "filesystem_bytes": shutil.disk_usage(root)._asdict(),
                    "cmp": common.capture([cmp, "--version"]).splitlines()[0],
                    "strace": common.capture([strace, "--version"]).splitlines()[0],
                    "runner_sha256": common.digest(Path(__file__)),
                    "reference_helper_sha256": {name: common.digest(Path(common.__file__).with_name(name))
                                                for name in ("common.py", "run.py")},
                    "cache": "warm source and prepared retained stage, one excluded warm-up per subject",
                    "repeats": args.repeats,
                })
                common.require(metadata["filesystem_bytes"]["free"] >= 2 * SIZE + 64 * MIB,
                               "reserve 320 MiB of fixture space")
                measure(binary, root, cmp, strace, args.repeats, report["evidence"])
                report["outcome"] = "passed"
        except BaseException as error:
            report.update(outcome="failed", reason=repr(error))
            raise
        finally:
            report["ended_utc"] = datetime.now(timezone.utc).isoformat()
            json.dump(report, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    main()

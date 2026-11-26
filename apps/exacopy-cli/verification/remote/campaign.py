#!/usr/bin/env python3
"""Exercise the compiled get/resume CLI against an independently qualified Linux fixture."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from fixture import (
    Blocked, Failed, JOB_NAME, MAX_QUALIFICATION, MAX_RECEIPT, MAX_REPORT, MAX_SOURCE,
    MIB, OMISSIONS, QUALIFICATION_DOMAIN, RECEIPT_DOMAIN,
    PeerLog, b3, canonical, check_held, checked_read, compare_files, digest_executable,
    file_sha256, fingerprint, hash_source, opened, owned_directory, peer_profile, require,
)
from process import CLEANUP_MARKER, owned_cli_process

ROOT = Path(__file__).resolve().parents[4]
METADATA = "sftp-data-only-v1"
RUN_TIMEOUT = 180
CUT_TIMEOUT = 90
MAX_JOURNAL = 8 * MIB
MAX_BINARY = 512 * MIB
FIRST_SEGMENT = Path("journal/00000000000000000001.exajnl")
RECEIPT = Path("receipts/receipt.cbor")
INCUMBENT = b"ExaCopy campaign incumbent, left byte-for-byte intact\n"
ROUTES = ("direct-pinned-tcp-v1", "embedded-wireguard-tcp-v1")


def git(*arguments):
    return subprocess.check_output(
        ["git", *arguments], cwd=ROOT, timeout=10, text=True,
    ).strip()


def sha256_artifacts(directory):
    return {
        f.name: file_sha256(f)
        for f in sorted(directory.iterdir())
        if f.is_file() and f.name != "summary.json"
    }


class HeldInputs:
    def __init__(self, scope):
        self._scope = scope
        self._held = {}

    def open(self, path, maximum, *, buffering=-1):
        file, info = opened(path, maximum, buffering=buffering)
        self._scope.enter_context(file)
        self._held[path] = (file, info, None)
        check_held(path, file, info)
        return file

    def read(self, path, maximum):
        file = self.open(path, maximum)
        _, info, _ = self._held[path]
        data = file.read(maximum + 1)
        require(len(data) == info.st_size, "selected protected input length changed")
        check_held(path, file, info)
        self._held[path] = (file, info, data)
        return data

    def recheck(self):
        for path, (file, info, data) in self._held.items():
            check_held(path, file, info)
            if data is not None:
                file.seek(0)
                require(file.read(len(data) + 1) == data, "selected protected input bytes changed")
                check_held(path, file, info)


def preflight(args, summary):
    if sys.platform != "linux" or platform.machine() not in ("aarch64", "x86_64"):
        raise Blocked("the campaign requires an admitted native Linux architecture")
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise Blocked("the source checkout must be clean")
    summary["revision"] = git("rev-parse", "HEAD")
    summary["tree"] = git("rev-parse", "HEAD^{tree}")
    summary["lock_sha256"] = file_sha256(ROOT / "Cargo.lock")
    summary["definition_sha256"] = {
        name: file_sha256(Path(__file__).with_name(name))
        for name in ("campaign.py", "fixture.py", "process.py")
    }
    dest = owned_directory(args.destination, private=True)
    if next(args.destination.iterdir(), None) is not None:
        raise Blocked("the exact attested destination must be an empty dedicated fixture root")
    if args.evidence.is_relative_to(args.destination):
        raise Blocked("evidence must be outside the dedicated destination")
    for operand in (
        args.binary, args.owner_profile, args.ssh_profile, args.qualification, args.trust,
        args.source_small, args.source_interrupt, args.sshd_log,
    ):
        if canonical(operand).is_relative_to(args.destination):
            raise Blocked("fixture inputs must be outside the dedicated destination")
    owned_directory(args.owner_profile, private=True)
    b3sum = shutil.which("b3sum")
    findmnt = shutil.which("findmnt")
    if not b3sum or not findmnt:
        raise Blocked("the independent b3sum and findmnt programs are required")
    mount = subprocess.run(
        [findmnt, "--json", "--target", str(args.destination),
         "--output", "FSTYPE,FSROOT,OPTIONS,TARGET"],
        capture_output=True, timeout=10, check=True,
    )
    filesystems = json.loads(mount.stdout)["filesystems"]
    if len(filesystems) != 1:
        raise Blocked("the destination must resolve to one selected mount")
    mounted = filesystems[0]
    if (
        mounted["fstype"] != "ext4" or mounted["fsroot"] != "/"
        or mounted["options"].split(",")[0] != "rw"
    ):
        raise Blocked("the selected mount is outside the whole writable ext4 profile")
    summary["native"] = {
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "root_device": dest.st_dev,
        "root_inode": dest.st_ino,
        "mount_namespace_inode": Path("/proc/self/ns/mnt").stat().st_ino,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "mount": mounted,
    }
    binary = args.inputs.open(args.binary, MAX_BINARY, buffering=0)
    if not os.access(args.binary, os.X_OK) or binary.read(4) != b"\x7fELF":
        raise Blocked("the selected compiled command is not executable ELF")
    summary["binary_build_digest"], summary["binary_sha256"] = digest_executable(binary, b3sum)
    if args.qualification == args.trust:
        raise Blocked("qualification and independently selected trust must be separate")
    trust = args.inputs.read(args.trust, MAX_REPORT)
    record = args.inputs.read(args.qualification, MAX_QUALIFICATION)
    profile = args.inputs.read(args.ssh_profile, MAX_REPORT)
    args.inputs.recheck()
    selection = json.loads(trust)
    if selection["route"] != args.route:
        raise Blocked("select separate qualification and trust artifacts for the exact route")
    if selection["build"] != summary["binary_build_digest"]:
        raise Blocked("the independent trust selects a different executable")
    summary["qualification_sha256"] = hashlib.sha256(record).hexdigest()
    summary["trust_sha256"] = hashlib.sha256(trust).hexdigest()
    summary["ssh_profile_sha256"] = hashlib.sha256(profile).hexdigest()
    digest = b3(b3sum, QUALIFICATION_DOMAIN + record)
    summary["qualification_digest"] = digest
    account, host, listener, port, local = peer_profile(profile, args.route)
    summary["peer_observation"] = {
        "listener": str(listener), "port": port,
        "required_source": "loopback" if local is None else str(local),
        "observed_scope": "dedicated-openssh-listener",
        "independent_outer_wireguard_observation": False,
    }
    return b3sum, digest, record, account, host, PeerLog(
        args.sshd_log, account, listener, port, local,
    )


def fixture_operand(account, host, path):
    if ":" in host:
        host = "[" + host + "]"
    return f"{account}@{host}:{path}"


def command_for(args, subcommand, operands, qualification):
    options = [
        "--profile", args.owner_profile, "--ssh-profile", args.ssh_profile,
        "--destination-qualification", qualification or args.qualification,
        "--qualification-trust", args.trust, "--metadata", METADATA, "--format", "json",
    ]
    return [args.binary, *subcommand, *options, "--", *operands]


def run_case(args, name, subcommand, operands, expected, *, cut=None, qualification=None):
    command = command_for(args, subcommand, operands, qualification)
    stdout = args.evidence / f"{name}.stdout"
    stderr = args.evidence / f"{name}.stderr"
    args.inputs.recheck()
    try:
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            with owned_cli_process(args.evidence, name, command, ROOT, output, errors) as process:
                observed = cut(process) if cut else None
                process.wait_for_exit(RUN_TIMEOUT)
    finally:
        args.inputs.recheck()
    status = process.returncode
    if expected == -signal.SIGKILL:
        require(status == expected, f"{name}: owned process did not exit by SIGKILL")
        return observed
    try:
        report = json.loads(checked_read(stdout, MAX_REPORT))
    except (OSError, ValueError, Blocked) as error:
        raise Failed(f"{name}: compiled CLI emitted no bounded JSON report (exit {status})") from error
    require(
        isinstance(report, dict) and report.get("schema") == "exacopy.cli.remote_download"
        and report.get("schema_version") == "1.0",
        f"{name}: wrong report schema",
    )
    if report.get("error", {}).get("code") == "E_AUTHORIZATION" and name == "get":
        raise Blocked("compiled CLI refused current independent qualification or source authority")
    require(status == expected, f"{name}: exit {status}, expected {expected}")
    return report


def selected_job(args, receipt):
    job = Path(receipt["job_directory"])
    require(
        job.parent == args.destination and JOB_NAME.fullmatch(job.name)
        and job.name == ".exacopy-" + receipt["job_id"],
        "report selected a job outside the exact retained fixture",
    )
    owned_directory(job, private=True)
    return job


def validate_published(args, name, report, source, facts, target, b3sum, qualification):
    source_info, digest = facts
    require(
        report["result"] == "published_with_omissions" and report["publication"] == "published"
        and report["completed"] == 1 and report["pending"] == 0
        and report["verification"] == "hash_readback" and report["consistency"] == "live_observed"
        and report["durability"] == "file_and_directory_barriers_observed"
        and report["durability_qualification"] == "process_crash_qualification"
        and report["preservation"] == "preserve" and report["metadata"] == "explicitly_omitted",
        f"{name}: the report assurance axes differ from the exact selection",
    )
    receipt = report["receipt"]
    require(
        receipt["length"] == str(source_info.st_size) and receipt["blake3"] == digest
        and receipt["qualification_digest"] == qualification
        and receipt["metadata_policy"] == METADATA and tuple(receipt["omissions"]) == OMISSIONS,
        f"{name}: report digest, qualification or metadata omissions differed",
    )
    target_info = compare_files(source, target, source_info)
    job = selected_job(args, receipt)
    actual = checked_read(canonical(job / RECEIPT), MAX_RECEIPT)
    require(
        len(actual) > 0 and receipt["receipt_digest"] == b3(b3sum, RECEIPT_DOMAIN + actual),
        f"{name}: associated physical receipt digest differed",
    )
    archive(args, name, job)
    return job, target_info


def archive(args, name, job):
    for label, source, bound in (
        ("journal", job / FIRST_SEGMENT, MAX_JOURNAL),
        ("receipt", job / RECEIPT, MAX_RECEIPT),
    ):
        if label == "receipt" and absent(source):
            continue
        with (args.evidence / f"{name}.{label}").open("xb") as out:
            out.write(checked_read(canonical(source), bound))


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def receipt_absent(job):
    directory = (job / RECEIPT).parent
    if absent(directory):
        return True
    require(stat.S_ISDIR(directory.lstat().st_mode), "private receipt directory is not a directory")
    owned_directory(directory, private=True)
    return absent(job / RECEIPT)


def namespace(root, expected, *, pending_job=False):
    found = set()
    for index, path in enumerate(root.iterdir()):
        require(index < 5, "unexpected entries in the isolated destination")
        found.add(path)
    extra = found - expected
    require(expected.issubset(found), "expected destination name disappeared")
    if pending_job:
        require(len(extra) <= 1, "multiple names appeared during the interrupted command")
        require(all(JOB_NAME.fullmatch(path.name) for path in extra), "unexpected destination name")
    else:
        require(not extra, "unexpected destination name")
    return next(iter(extra), None)


def cut_partial(process, destination, target, known, length):
    deadline = time.monotonic() + CUT_TIMEOUT
    candidate = None
    while time.monotonic() < deadline and not process.exited():
        job = namespace(destination, known, pending_job=True)
        if job is not None:
            owned_directory(job, private=True)
            directory = job / "stage"
            if not absent(directory):
                owned_directory(directory, private=True)
                stages = set()
                for index, file in enumerate(directory.iterdir()):
                    require(index == 0, "multiple stages appeared before the process cut")
                    require(file.name.startswith("capture-"), "unexpected private stage name")
                    stages.add(file)
                if stages:
                    stage = stages.pop()
                    info = stage.lstat()
                    if stat.S_ISREG(info.st_mode) and 0 < info.st_size < length:
                        candidate = (job, stage)
                        break
        process.pump()
    if candidate is None:
        raise Failed("no bounded partial native stage was observed before the process cut")
    process.confirm_stopped()
    job, stage = candidate
    info = stage.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size < length
        and absent(target) and receipt_absent(job),
        "the stopped native process did not retain a partial, pre-public stage",
    )
    namespace(destination, known | {job})
    process.signal(signal.SIGKILL)
    return job, stage, info


def record_case(args, summary, peer, name, connections):
    peer.check(connections, args.evidence / f"{name}.openssh.log")
    summary["cases"].append({"name": name, "outcome": "pass", "connections": connections})


def cases(args, summary):
    with ExitStack() as scope:
        args.inputs = HeldInputs(scope)
        run_campaign(args, summary)


def run_campaign(args, summary):
    b3sum, qualification, record, account, host, peer = preflight(args, summary)
    small = hash_source(args.source_small, b3sum, 0, 0)
    large = hash_source(args.source_interrupt, b3sum, 8 * MIB, MAX_SOURCE)
    small_operand = fixture_operand(account, host, args.source_small)
    large_operand = fixture_operand(account, host, args.source_interrupt)
    target = args.destination / "complete"
    interrupted = args.destination / "interrupted"
    incumbent = args.destination / "incumbent"
    summary["fixture_ready"] = True
    summary["source_inputs"] = {
        "empty": {"length": small[0].st_size, "blake3": small[1]},
        "interrupt": {"length": large[0].st_size, "blake3": large[1]},
    }

    owned_directory(args.qualification.parent, private=True)
    with incumbent.open("xb") as fixture:
        fixture.write(INCUMBENT)
    original_incumbent = incumbent.stat()

    require(bool(record), "selected qualification artifact is empty")
    with tempfile.NamedTemporaryFile(prefix="signature-control-", dir=args.qualification.parent) as copy:
        copy.write(record)
        copy.flush()
        same_path = Path(copy.name)
        original_control = os.fstat(copy.fileno())
        require(checked_read(same_path, MAX_QUALIFICATION) == record, "control bytes changed")
        check_held(same_path, copy, original_control)
        name = "qualification-path-control"
        control = run_case(args, name, ("get",), (small_operand, incumbent), 3, qualification=same_path)
        require(
            control["publication"] == "not_published" and control["error"]["code"] == "E_CONFLICT",
            "the exact unmodified signed control path did not pass qualification",
        )
        check_held(same_path, copy, original_control)
        namespace(args.destination, {incumbent})
        record_case(args, summary, peer, name, 0)
        changed = record[:-1] + bytes([record[-1] ^ 1])
        copy.seek(0)
        copy.write(changed)
        copy.flush()
        corrupted_control = os.fstat(copy.fileno())
        require(
            (corrupted_control.st_dev, corrupted_control.st_ino)
            == (original_control.st_dev, original_control.st_ino),
            "signature control changed native identity",
        )
        require(checked_read(same_path, MAX_QUALIFICATION) == changed, "corrupted signature bytes changed")
        check_held(same_path, copy, corrupted_control)
        name = "qualification-refusal"
        failure = run_case(args, name, ("get",), (small_operand, incumbent), 8, qualification=same_path)
        check_held(same_path, copy, corrupted_control)
    require(
        failure["publication"] == "not_published" and failure["error"]["code"] == "E_AUTHORIZATION",
        "corrupted qualification signature was not refused",
    )
    namespace(args.destination, {incumbent})
    record_case(args, summary, peer, name, 0)

    name = "get"
    report = run_case(args, name, ("get",), (small_operand, target), 11)
    first, _ = validate_published(args, name, report, args.source_small, small, target, b3sum, qualification)
    namespace(args.destination, {first, target, incumbent})
    record_case(args, summary, peer, name, 1)

    name = "incumbent"
    failure = run_case(args, name, ("get",), (small_operand, incumbent), 3)
    require(
        failure["publication"] == "not_published" and failure["error"]["code"] == "E_CONFLICT"
        and checked_read(incumbent, len(INCUMBENT)) == INCUMBENT
        and fingerprint(incumbent.stat()) == fingerprint(original_incumbent),
        "incumbent refusal modified the fixture or admitted a new job",
    )
    namespace(args.destination, {first, target, incumbent})
    record_case(args, summary, peer, name, 0)

    name = "process-kill"
    job, stage, stopped = run_case(
        args, name, ("get",), (large_operand, interrupted), -signal.SIGKILL,
        cut=lambda process: cut_partial(process, args.destination, interrupted, {first, target, incumbent}, large[0].st_size),
    )
    require(absent(interrupted), "process-killed capture published a target")
    retained = hash_source(stage, b3sum, 1, large[0].st_size - 1)
    require(fingerprint(retained[0]) == fingerprint(stopped), "partial stage changed after SIGKILL")
    summary["interruption"] = {
        "signal": "SIGKILL", "partial_length": stopped.st_size, "blake3": retained[1],
    }
    archive(args, name, job)
    record_case(args, summary, peer, name, 1)

    name = "resume"
    report = run_case(args, name, ("recover", "remote-resume"), (job,), 11)
    resumed, result = validate_published(
        args, name, report, args.source_interrupt, large, interrupted, b3sum, qualification,
    )
    require(resumed == job, "resume used another job")
    namespace(args.destination, {first, job, target, incumbent, interrupted})
    require(
        fingerprint(stage.stat()) == fingerprint(stopped)
        and hash_source(stage, b3sum, 1, large[0].st_size - 1)[1] == retained[1],
        "resume changed the retained partial stage",
    )
    record_case(args, summary, peer, name, 1)

    name = "post-intent"
    failure = run_case(args, name, ("recover", "remote-resume"), (job,), 9)
    require(
        failure["publication"] == "published" and failure["error"]["code"] == "E_RECOVERY_REQUIRED"
        and fingerprint(interrupted.stat()) == fingerprint(result),
        "historical published job was retried, modified, or reported incorrectly",
    )
    namespace(args.destination, {first, job, target, incumbent, interrupted})
    for name_part, relative, limit in (("journal", FIRST_SEGMENT, MAX_JOURNAL), ("receipt", RECEIPT, MAX_RECEIPT)):
        require(
            checked_read(canonical(job / relative), limit)
            == checked_read(args.evidence / f"resume.{name_part}", limit),
            "post-intent invocation changed retained authoritative evidence",
        )
    record_case(args, summary, peer, name, 0)

    compare_files(args.source_small, target, small[0])
    compare_files(args.source_interrupt, interrupted, large[0])
    require(checked_read(incumbent, len(INCUMBENT)) == INCUMBENT, "final incumbent bytes differed")
    args.inputs.recheck()


def cleanup_status(evidence, summary, status):
    if not absent(evidence / CLEANUP_MARKER):
        if "reason" in summary:
            summary["prior_reason"] = summary["reason"]
        summary["status"] = "blocked"
        summary["reason"] = "owned nested CLI process cleanup is unconfirmed"
        return 77
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary", "destination", "owner-profile", "ssh-profile", "qualification",
        "trust", "source-small", "source-interrupt", "sshd-log", "evidence",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--route", choices=ROUTES, required=True)
    args = parser.parse_args()
    args.evidence = args.evidence.absolute()
    if args.evidence.resolve().is_relative_to(args.destination.resolve()):
        parser.error("evidence directory may not touch the dedicated destination")
    try:
        owned_directory(args.evidence.parent)
        args.evidence.mkdir(mode=0o700, exist_ok=False)
    except (Blocked, OSError) as error:
        parser.error(f"invalid or occupied evidence destination ({type(error).__name__})")
    summary = {
        "schema": "exacopy.linux-remote-cli-campaign.v1",
        "route": args.route,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "cases": [],
        "status": "blocked",
        "issues_new_qualification": False,
    }
    status = 77
    try:
        cases(args, summary)
        summary["status"], status = "pass", 0
    except Blocked as error:
        summary["reason"] = str(error)
    except Failed as error:
        summary["status"], status = "fail", 1
        summary["reason"] = str(error)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        summary["status"], status = ("fail", 1) if summary.get("fixture_ready") else ("blocked", 77)
        summary["reason"] = type(error).__name__
    finally:
        status = cleanup_status(args.evidence, summary, status)
        summary["finished_at"] = datetime.now(timezone.utc).isoformat()
        summary["exit_status"] = status
        summary["artifacts_sha256"] = sha256_artifacts(args.evidence)
        with (args.evidence / "summary.json").open("x") as file:
            json.dump(summary, file, indent=2, sort_keys=True)
            file.write("\n")
    return status


if __name__ == "__main__":
    sys.exit(main())

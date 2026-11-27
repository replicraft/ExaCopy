"""Observe retained retry custody and the ordinary remote-resume admission boundary."""

import json
import os
from pathlib import Path
import re
import stat
import time

from campaign import FIRST_SEGMENT, MAX_JOURNAL, ROOT, absent, command_for, namespace, receipt_absent
from fixture import MAX_REPORT, canonical, check_held, checked_read, opened, owned_directory, require
from process import owned_cli_process

STAGE_NAME = re.compile(r"capture-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
RESUME_CONTROLS = ("resume-published", "resume-incumbent", "resume-qualification-refusal")
RESUME_CONTROL_TIMEOUT = 30
RESUME_INCUMBENT = b"preserve the isolated retry campaign incumbent\n"


def stages(job):
    directory = job / "stage"
    owned_directory(directory, private=True)
    found = set()
    for file in directory.iterdir():
        require(len(found) < 3 and STAGE_NAME.fullmatch(file.name), "unexpected stage namespace")
        require(stat.S_ISREG(file.lstat().st_mode), "stage is not a regular file")
        found.add(file)
    return found


def read_terminal(source, destination, exit_status, elapsed):
    observation = {
        "exit_status": exit_status,
        "elapsed_seconds": round(elapsed, 3),
        "report_schema_valid": False,
        "result": None,
        "publication": None,
        "error_code": None,
    }
    try:
        report = json.loads(checked_read(canonical(source), MAX_REPORT))
        require(isinstance(report, dict) and report.get("schema") == "exacopy.cli.remote_download"
                and report.get("schema_version") == "1.0", "wrong public report schema")
        observation["report_schema_valid"] = True
        if (result := report.get("result")) in ("failed", "published_with_omissions"):
            observation["result"] = result
        if (publication := report.get("publication")) in ("not_published", "published", "publication_uncertain"):
            observation["publication"] = publication
        error = report.get("error")
        if isinstance(error, dict) and (code := error.get("code")) in (
            "E_INVALID_REQUEST", "E_CONFLICT", "E_IO", "E_INTEGRITY", "E_UNSUPPORTED",
            "E_AUTHORIZATION", "E_RECOVERY_REQUIRED", "E_CANCELLED",
        ):
            observation["error_code"] = code
        return report
    finally:
        # Retain the closed process's disposition before any peer oracle can fail.
        # The fixture's paths, stderr and full report stay in the private workspace.
        with destination.open("x", encoding="utf-8") as output:
            json.dump(observation, output, sort_keys=True)
            output.write("\n")


def resume_control(args, name, job, expected, code, publication, peer, trace, *, qualification=None):
    argv = command_for(args, ("recover", "remote-resume"), (job,), qualification)
    stdout, stderr = (args.evidence / f"{name}.{stream}" for stream in ("stdout", "stderr"))
    args.inputs.recheck()
    before_peer = trace.snapshot()
    journal_path = canonical(job / FIRST_SEGMENT)
    journal, identity = opened(journal_path, MAX_JOURNAL)
    with journal:
        before_journal = journal.read(MAX_JOURNAL + 1)
        require(len(before_journal) == identity.st_size, "original journal changed during preflight")
        check_held(journal_path, journal, identity)
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            with owned_cli_process(args.evidence, name, argv, ROOT, output, errors) as process:
                started = time.monotonic()
                process.wait_for_exit(RESUME_CONTROL_TIMEOUT)
                elapsed = time.monotonic() - started
        report = read_terminal(stdout, args.evidence / f"{name}.terminal.json", process.returncode, elapsed)
        # A direct connection must be observed before the SSH client can offer
        # any credential or open an SFTP subsystem. Assert the listener count,
        # including connections that never authenticated.
        peer.check(0, args.evidence / f"{name}.openssh.log")
        require(trace.snapshot() == before_peer, "resume refusal submitted a fixture SFTP request")
        require(
            process.returncode == expected and report["result"] == "failed"
            and report["publication"] == publication and report["error"]["code"] == code
            and Path(report["error"]["job_directory"]) == job
            and report["error"]["job_id"] == job.name.removeprefix(".exacopy-"),
            "resume refusal changed the terminal disposition or retained-job custody",
        )
        journal.seek(0)
        require(journal.read(MAX_JOURNAL + 1) == before_journal,
                "resume refusal changed the original journal")
        check_held(journal_path, journal, identity)
    args.inputs.recheck()


def resume_against_incumbent(args, retained, target, peer, trace, known):
    namespace(args.destination, known)
    require(absent(target) and receipt_absent(retained.job),
            "expired capture already has a publication or receipt")
    with target.open("x+b") as incumbent:
        incumbent.write(RESUME_INCUMBENT)
        incumbent.flush()
        info = os.fstat(incumbent.fileno())
        try:
            resume_control(args, "resume-incumbent", retained.job, 3, "E_CONFLICT",
                           "not_published", peer, trace)
            # Passing the exact trust path as the attestation also violates
            # qualification selection. The qualification refusal must win
            # over the same positively occupied target.
            resume_control(args, "resume-qualification-refusal", retained.job, 9,
                           "E_RECOVERY_REQUIRED", "publication_uncertain",
                           peer, trace, qualification=args.trust)
            incumbent.seek(0)
            require(incumbent.read(len(RESUME_INCUMBENT) + 1) == RESUME_INCUMBENT,
                    "resume refusal modified the private fixture incumbent")
            retained.recheck()
            require(stages(retained.job) == {retained.name} and receipt_absent(retained.job),
                    "resume refusal created another stage or receipt")
            namespace(args.destination, {*known, target})
        finally:
            check_held(target, incumbent, info)
            target.unlink()

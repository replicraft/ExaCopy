#!/usr/bin/env python3
"""Observe guarded redial by the ordinary native CLI with one withheld SFTP READ."""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from campaign import (
    HeldInputs, MAX_RECEIPT, RECEIPT, ROOT, absent, archive, cleanup_status, command_for, fixture_operand,
    namespace, preflight, receipt_absent, sha256_artifacts, validate_published,
)
from fixture import (
    AUTHENTICATION, CONNECTION, MAX_PEER_LOG, MAX_REPORT, Blocked, Failed, b3, canonical,
    check_held, checked_read, file_sha256, fingerprint, match_records,
    opened, owned_directory, require,
)
from process import owned_cli_process
from retry_observations import read_terminal, resume_against_incumbent, resume_control, stages

DIRECT = "direct-pinned-tcp-v1"
WINDOW = 64 * 1024
SOURCE_BYTES = 3 * WINDOW
MAX_TRACE = 64 * 1024
EVENT = re.compile(
    r"(redial|expired|revoked|budget|host-refused) ([1-4]) "
    r"(open|read|fstat|lstat|close|eof|timeout-held|new-zero-held|released|transport-closed|peer-budget) "
    r"([0-9]{1,8}) ([0-9]{1,5}) ([0-9]{1,15})"
)
CASES = (
    ("redial", 90),
    ("expired", 10),
    ("revoked", 90),
    ("budget", 52),
    ("host-refused", 90),
)


@dataclass(frozen=True)
class Event:
    case: str
    attempt: int
    kind: str
    offset: int
    length: int
    stamp: int


def parse_trace(data):
    require(not data or data.endswith(b"\n"), "partial event record")
    rows = []
    for line in data.decode("ascii", errors="strict").splitlines():
        row = EVENT.fullmatch(line)
        require(row is not None, "unrecognized SFTP fixture event")
        name, attempt, kind, offset, length, stamp = row.groups()
        rows.append(Event(name, int(attempt), kind, int(offset), int(length), int(stamp)))
    return rows


class Trace:
    def __init__(self, path):
        self.path = canonical(path)
        opened_log, before = opened(self.path, MAX_TRACE)
        opened_log.close()
        require(before.st_size == 0, "fault trace must be freshly empty")
        self.identity = before.st_dev, before.st_ino
        self.prior = b""

    def snapshot(self):
        stream, info = opened(self.path, MAX_TRACE)
        with stream:
            require(self.identity == (info.st_dev, info.st_ino), "fault trace replaced")
            raw = stream.read(info.st_size)
        require(raw.startswith(self.prior), "fault trace rewound or changed")
        rows = parse_trace(raw)
        self.prior = raw
        return rows

    def until(self, process, deadline, predicate, description):
        while time.monotonic() < deadline:
            value = predicate(self.snapshot())
            if value is not None:
                return value
            require(not process.exited(), description)
            process.pump()
        raise Failed(description)


def one(rows, name, attempt, kind):
    found = [row for row in rows if (row.case, row.attempt, row.kind) == (name, attempt, kind)]
    require(len(found) <= 1, f"duplicate {kind} event for one fixture session")
    return found[0] if found else None


def wait_event(trace, process, deadline, name, attempt, event):
    return trace.until(
        process, deadline, lambda rows: one(rows, name, attempt, event),
        f"{name}: did not reach {event} on authenticated session {attempt}",
    )


@dataclass
class PreviousStage:
    job: Path
    name: Path
    file: object
    observed: os.stat_result
    digest: str

    def recheck(self):
        check_held(self.name, self.file, self.observed)
        self.file.seek(0)
        current = hashlib.sha256(self.file.read(WINDOW + 1)).hexdigest()
        check_held(self.name, self.file, self.observed)
        require(current == self.digest, "retained stage contents changed")


def pin_previous(scope, destination, target, known, source):
    job = namespace(destination, known, pending_job=True)
    require(job is not None, "held READ did not establish one private job")
    owned_directory(job, private=True)
    names = stages(job)
    require(len(names) == 1 and absent(target) and receipt_absent(job), "first stage not pre-intent")
    stage = names.pop()
    stream, identity = opened(stage, WINDOW)
    scope.enter_context(stream)
    require(identity.st_size == WINDOW and identity.st_uid == os.geteuid(), "incorrect native prefix")
    content = stream.read(WINDOW + 1)
    source.seek(0)
    require(content == source.read(WINDOW), "old stage differs from independent source prefix")
    retained = PreviousStage(job, stage, stream, identity, hashlib.sha256(content).hexdigest())
    retained.recheck()
    return retained


def release_new(scope, args, retained, target):
    candidates = stages(retained.job) - {retained.name}
    require(len(candidates) == 1 and absent(target) and receipt_absent(retained.job), "new stage not isolated")
    second = candidates.pop()
    fresh, info = opened(second, 0)
    scope.enter_context(fresh)
    require(
        info.st_size == 0 and info.st_nlink == 1 and info.st_uid == os.geteuid()
        and (info.st_dev, info.st_ino) != (retained.observed.st_dev, retained.observed.st_ino),
        "fresh source did not wait over a distinct empty native stage",
    )
    retained.recheck()
    check_held(second, fresh, info)
    require(absent(args.release_path), "fault control was already released")
    with args.release_path.open("xb"):
        pass
    return fresh, (info.st_dev, info.st_ino)


def observed_profile(args, name, grant, base_profile):
    path = args.ssh_profile.parent / f"retry-{name}.json"
    profile = dict(base_profile, grant_seconds=grant)
    if name == "host-refused":
        pin = profile["host_key_sha256"]
        profile["host_key_sha256"] = ("1" if pin[0] == "0" else "0") + pin[1:]
    with path.open("x", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(profile, output, separators=(",", ":"))
        output.write("\n")
    args.inputs.read(path, MAX_REPORT)
    return path


def refuse_host(peer, output):
    log, info = opened(peer.path, MAX_PEER_LOG)
    with log:
        require((info.st_dev, info.st_ino) == peer.identity and info.st_size >= peer.offset,
                "OpenSSH log custody changed")
        log.seek(peer.offset)
        data = log.read(info.st_size - peer.offset)
    connections = match_records(data, CONNECTION)
    accepted = match_records(data, AUTHENTICATION)
    require(len(connections) == 1 and accepted == [], "wrong pinned host redialed or authenticated")
    origin, _, address, port = connections[0]
    require(ipaddress.ip_address(origin).is_loopback and ipaddress.ip_address(address) == peer.listener
            and int(port) == peer.port, "wrong pin used a different route")
    with output.open("xb") as destination:
        destination.write(data)


def report_code(report, actual, allowed):
    code = report.get("error", {}).get("code")
    require(
        report.get("result") == "failed" and report.get("publication") == "not_published"
        and (actual, code) in allowed,
        "compiled CLI emitted an unexpected terminal disposition",
    )
    return code


def require_closed(rows, name, attempts):
    for attempt in attempts:
        require(one(rows, name, attempt, "open") is not None,
                f"{name}: no SFTP open observed on expected session {attempt}")
        require(one(rows, name, attempt, "timeout-held") is not None,
                f"{name}: no held READ observed on expected session {attempt}")
        require(one(rows, name, attempt, "transport-closed") is not None,
                f"{name}: no closure observed after a held READ on session {attempt}")


def peer_pass(rows, name, attempts):
    selected = [event for event in rows if event.case == name]
    require(not any(event.kind == "peer-budget" for event in selected), "fault peer timed out first")
    require([event.attempt for event in selected if event.kind == "open"] == attempts,
            "unplanned SFTP session")
    for attempt in attempts:
        reads = [event.offset for event in selected if event.attempt == attempt and event.kind == "read"]
        require(reads and reads[0] == 0, "first read of the authenticated source was not at byte zero")
    return selected


def case(args, name, grant, b3sum, qualification, account, host, peer, trace, known, profile):
    target = args.destination / f"{name}-target"
    source = args.sources / name
    held_source = args.inputs.open(canonical(source), SOURCE_BYTES, buffering=0)
    info = os.fstat(held_source.fileno())
    require(info.st_size == SOURCE_BYTES and info.st_uid == os.geteuid(), "source is outside fixture scope")
    digest = b3(b3sum, None, file=held_source)
    check_held(source, held_source, info)
    chosen = observed_profile(args, name, grant, profile)
    argv = command_for(args, ("get",), (fixture_operand(account, host, f"/retry-input/{name}"), target), None)
    argv[argv.index("--ssh-profile") + 1] = chosen
    stdout, stderr = (args.evidence / f"{name}.{stream}" for stream in ("stdout", "stderr"))
    args.inputs.recheck()

    with ExitStack() as observation:
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            with owned_cli_process(args.evidence, name, argv, ROOT, output, errors) as process:
                started = time.monotonic()
                retained = first = second = fresh = fresh_identity = None
                if name != "host-refused":
                    first = wait_event(trace, process, started + 8, name, 1, "timeout-held")
                    require(first.offset == WINDOW, "fault did not target the second application window")
                    retained = pin_previous(observation, args.destination, target, known, held_source)
                if name == "redial":
                    second = wait_event(trace, process, started + 40, name, 2, "new-zero-held")
                    require(second.offset == 0, "fresh source attempted to skip the old prefix")
                    fresh, fresh_identity = release_new(observation, args, retained, target)
                if name == "revoked":
                    process.signal(signal.SIGINT)
                process.wait_for_exit(grant + 8)
                elapsed = time.monotonic() - started
        report = read_terminal(stdout, args.evidence / f"{name}.terminal.json", process.returncode, elapsed)
        args.inputs.recheck()
        require(fingerprint(source.stat(follow_symlinks=False)) == fingerprint(info), "source changed")
        end = time.monotonic() + 2
        rows = trace.snapshot()
        if retained is not None:
            expected_closed = (1, 2, 3) if name == "budget" else (1,)
            while (any(one(rows, name, attempt, "transport-closed") is None for attempt in expected_closed)
                   and time.monotonic() < end):
                time.sleep(0.01)
                rows = trace.snapshot()
            require_closed(rows, name, expected_closed)
            closed = one(rows, name, 1, "transport-closed")
            retained.recheck()
            known.add(retained.job)
        if name == "redial":
            require(process.returncode == 11, "guarded READ timeout did not produce a successful redial")
            require(19000 <= closed.stamp - first.stamp <= 25000 and second.stamp >= closed.stamp,
                    "old read did not time out before a fresh authenticated read")
            job, final = validate_published(args, name, report, source, (info, digest), target, b3sum, qualification)
            require(job == retained.job and stages(job) == {retained.name},
                    "publication did not retain the old job and stage")
            selected = peer_pass(rows, name, [1, 2])
            tail = [row.kind for row in selected if row.attempt == 2][-4:]
            require(tail == ["eof", "fstat", "close", "lstat"], "missing exact terminal SFTP observation")
            retained.recheck()
            require((final.st_dev, final.st_ino) == fresh_identity, "publication lost the fresh stage identity")
            check_held(target, fresh, final)
            known.add(target)
            peer.check(2, args.evidence / f"{name}.openssh.log")
            count, status = 2, "published_with_omissions"
            resume_control(args, "resume-published", job, 9, "E_RECOVERY_REQUIRED",
                           "published", peer, trace)
            check_held(target, fresh, final)
            retained.recheck()
            require(stages(job) == {retained.name}
                    and checked_read(canonical(job / RECEIPT), MAX_RECEIPT)
                    == checked_read(args.evidence / f"{name}.receipt", MAX_RECEIPT),
                    "published resume changed private stages or the committed receipt")
        elif name == "host-refused":
            status = report_code(report, process.returncode, {(8, "E_AUTHORIZATION")})
            peer_pass(rows, name, [])
            refuse_host(peer, args.evidence / f"{name}.openssh.log")
            count = 1
        else:
            allowed = {(9, "E_RECOVERY_REQUIRED"), (10, "E_CANCELLED")} if name == "revoked" else {
                (8, "E_AUTHORIZATION"), (9, "E_RECOVERY_REQUIRED"),
            }
            status = report_code(report, process.returncode, allowed)
            attempts = [1, 2, 3] if name == "budget" else [1]
            peer_pass(rows, name, attempts)
            if name == "expired":
                require(elapsed >= grant - 1 and closed.stamp - first.stamp < 19000,
                        "expiry did not stop the held request before its read deadline")
            if name == "revoked":
                require(closed.stamp - first.stamp < 5000, "explicit revocation did not fence the held read")
            if name == "budget":
                for attempt in (1, 2):
                    attempt_held = one(rows, name, attempt, "timeout-held")
                    actual_close = one(rows, name, attempt, "transport-closed")
                    require(attempt_held is not None and actual_close is not None
                            and 19000 <= actual_close.stamp - attempt_held.stamp <= 25000,
                            "original grant did not cover both bounded held read timeouts")
                require(grant - 1 <= elapsed <= grant + 7, "attempts renewed or bypassed the original grant")
            require(absent(target) and receipt_absent(retained.job), "failed retry reached public effects")
            require(len(stages(retained.job)) == len(attempts), "one bounded allocation per admitted attempt")
            require(Path(report["error"]["job_directory"]) == retained.job,
                    "terminal report lost the exact original job")
            archive(args, name, retained.job)
            count = len(attempts)
            peer.check(count, args.evidence / f"{name}.openssh.log")
            if name == "expired":
                resume_against_incumbent(args, retained, target, peer, trace, known)
        namespace(args.destination, known)
        return {
            "case": name, "status": status, "connections": count, "elapsed_seconds": round(elapsed, 3),
            "retained_stage_sha256": retained.digest if retained else None,
            "retained_stage_device": retained.observed.st_dev if retained else None,
            "retained_stage_inode": retained.observed.st_ino if retained else None,
            "fresh_published_inode": fresh_identity[1] if fresh_identity else None,
            "source_blake3": digest,
        }


def run(args, summary):
    with ExitStack() as scope:
        args.route = DIRECT
        # Shared native/binary/attestation preflight. The retry campaign has a
        # distinct bounded source set and uses no fixture it cannot reobserve.
        args.source_small = args.source_interrupt = args.sources / "redial"
        args.inputs = HeldInputs(scope)
        b3sum, qualification, _, account, host, peer = preflight(args, summary)
        require(not args.trace.is_relative_to(args.destination), "fault evidence overlaps destination")
        owned_directory(args.release_path.parent)
        require(args.release_path.name == "release-redial" and absent(args.release_path), "invalid release slot")
        profile = json.loads(args.inputs.read(args.ssh_profile, MAX_REPORT))
        trace = Trace(args.trace)
        summary["definition_sha256"].update({
            name: file_sha256(Path(__file__).with_name(name))
            for name in ("retry_campaign.py", "retry_observations.py", "retry_sftp_peer.c")
        })
        summary["fixture_ready"] = True
        known = set()
        initial_peer_offset = peer.offset
        try:
            for name, duration in CASES:
                summary["cases"].append(
                    case(args, name, duration, b3sum, qualification, account, host, peer, trace, known, profile)
                )
            args.inputs.recheck()
        finally:
            with (args.evidence / "sftp-events.log").open("xb") as out:
                # Preserve the last validated prefix even when the fixture fails.
                out.write(trace.prior)
            server_log, observed = opened(peer.path, MAX_PEER_LOG)
            with server_log:
                require((observed.st_dev, observed.st_ino) == peer.identity
                        and observed.st_size >= initial_peer_offset, "OpenSSH log custody changed")
                server_log.seek(initial_peer_offset)
                seen = server_log.read(MAX_TRACE + 1)
                require(len(seen) <= MAX_TRACE, "fixture transcript exceeds the artifact budget")
            with (args.evidence / "openssh.log").open("xb") as out:
                out.write(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "destination", "owner-profile", "ssh-profile", "qualification",
                 "trust", "sources", "sshd-log", "trace", "release-path", "evidence"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    for value in vars(args).values():
        if not value.is_absolute():
            parser.error("all fixture paths must be absolute")
    if args.evidence.resolve().is_relative_to(args.destination.resolve()):
        parser.error("evidence directory may not touch the dedicated destination")
    try:
        owned_directory(args.evidence.parent)
        args.evidence.mkdir(mode=0o700, exist_ok=False)
    except (Blocked, OSError) as error:
        parser.error(f"invalid or occupied evidence path ({type(error).__name__})")
    summary = {
        "schema": "exacopy.linux-remote-read-timeout.v1", "status": "blocked", "cases": [],
        "qualifies_remote_download": False, "issues_new_qualification": False,
        "verified_range_reuse": False,
        "observed_route": DIRECT, "outer_wireguard_observed": False,
    }
    status = 77
    try:
        run(args, summary)
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
        summary["exit_status"] = status
        summary["artifacts_sha256"] = sha256_artifacts(args.evidence)
        with (args.evidence / "summary.json").open("x", encoding="utf-8") as output:
            json.dump(summary, output, indent=2, sort_keys=True)
            output.write("\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())

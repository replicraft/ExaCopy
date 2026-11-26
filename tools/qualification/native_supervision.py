"""Bounded owned subprocess groups and retained native qualification transcripts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

LOG_LIMIT = 32 * 1024 * 1024
TERM_GRACE = 8.0
POLL_INTERVAL = 0.05
READ_CHUNK = 64 * 1024
CANCELLATION_REQUESTED = False


@dataclass(frozen=True)
class ProcessResult:
    status: str
    exit_status: int | None = None

    def passed(self) -> bool:
        return self.status == "exited" and self.exit_status == 0


class CleanupUnconfirmed(RuntimeError):
    """The owned process group did not drain within the cleanup budget."""


def group_exists(leader: int) -> bool:
    try:
        os.killpg(leader, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # A group we cannot signal must still prevent a clean-drain claim.
        return True
    return True


def group_signal(leader: int, sig: int) -> None:
    try:
        os.killpg(leader, sig)
    except ProcessLookupError:
        pass


def leader_exited(process: subprocess.Popen) -> bool:
    try:
        event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise CleanupUnconfirmed("ownership of the unreaped leader could not be established") from error
    return event is not None and event.si_pid == process.pid


def wait_before_reaping(process: subprocess.Popen, budget: float) -> None:
    deadline = time.monotonic() + budget
    while not leader_exited(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, POLL_INTERVAL))


def group_drained(leader: int, budget: float) -> bool:
    deadline = time.monotonic() + budget
    while group_exists(leader):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, POLL_INTERVAL))
    return True


def stop_group(process: subprocess.Popen, initial: int) -> bool:
    # WNOWAIT retains the original session-leader PID across every real signal.
    # Reap only after the last signal. Subsequent group checks are nonmutating.
    already_exited = leader_exited(process)
    try:
        if initial != signal.SIGKILL and not already_exited:
            group_signal(process.pid, initial)
            wait_before_reaping(process, TERM_GRACE)
        group_signal(process.pid, signal.SIGKILL)
    except (OSError, KeyboardInterrupt) as error:
        if not leader_exited(process):
            raise CleanupUnconfirmed("owned group could not be signalled") from error
    try:
        process.wait(timeout=TERM_GRACE)
    except subprocess.TimeoutExpired as error:
        raise CleanupUnconfirmed("owned leader was not reaped") from error
    immediate_drain = group_drained(process.pid, 0)
    if not immediate_drain and not group_drained(process.pid, TERM_GRACE):
        raise CleanupUnconfirmed("owned process group did not drain")
    return immediate_drain


def stream(process: subprocess.Popen, transcript, timeout: float, output_limit: int) -> ProcessResult:
    deadline = time.monotonic() + timeout
    remaining_extent = output_limit
    with selectors.DefaultSelector() as readiness:
        readiness.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if CANCELLATION_REQUESTED:
                return ProcessResult("interrupted")
            if not readiness.get_map():
                if leader_exited(process):
                    return ProcessResult("exited")
                time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))
                continue
            budget = min(POLL_INTERVAL, max(0, deadline - time.monotonic()))
            if not readiness.select(budget):
                continue
            chunk = os.read(process.stdout.fileno(), min(READ_CHUNK, remaining_extent + 1))
            if not chunk:
                readiness.unregister(process.stdout)
                continue
            prefix = chunk[:remaining_extent]
            if transcript.write(prefix) != len(prefix):
                raise OSError("incomplete retained native transcript write")
            if len(chunk) > remaining_extent:
                return ProcessResult("output-limit")
            remaining_extent -= len(chunk)
    return ProcessResult("timeout")


def logged_command(
    command, log: Path, timeout: float, *, cwd: Path | None = None, env=None,
    output_limit: int = LOG_LIMIT, soft_signal: int = signal.SIGTERM,
) -> ProcessResult:
    try:
        with log.open("xb", buffering=0) as transcript:
            if CANCELLATION_REQUESTED:
                return ProcessResult("interrupted")
            try:
                child = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                    cwd=cwd, stdin=subprocess.DEVNULL, start_new_session=True,
                )
            except OSError:
                return ProcessResult("startup-failed")
            try:
                try:
                    result = stream(child, transcript, timeout, output_limit)
                except KeyboardInterrupt:
                    result = ProcessResult("interrupted")
                except CleanupUnconfirmed:
                    raise
                except BaseException:
                    stop_group(child, soft_signal)
                    raise
                if result.status == "exited":
                    drained = stop_group(child, signal.SIGKILL)
                    if CANCELLATION_REQUESTED:
                        status = "interrupted"
                    else:
                        status = "exited" if drained else "stray-descendant"
                    return ProcessResult(status, child.returncode)
                stop_group(child, soft_signal)
                return ProcessResult(result.status, child.returncode)
            finally:
                child.stdout.close()
    except CleanupUnconfirmed as unresolved:
        try:
            write_json(log.with_suffix(".cleanup.json"), process_record(
                ProcessResult("cleanup-unconfirmed"), log,
            ))
        finally:
            # Evidence I/O cannot convert unresolved ownership into ordinary failure.
            raise unresolved


def file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path: Path, report: dict) -> None:
    with path.open("x", encoding="ascii") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def process_record(result: ProcessResult, log: Path) -> dict:
    return {
        "status": result.status, "exit_status": result.exit_status,
        "log_sha256": file_digest(log),
    }


def interrupted(_signum, _frame):
    global CANCELLATION_REQUESTED
    CANCELLATION_REQUESTED = True

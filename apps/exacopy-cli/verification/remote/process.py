"""Bounded runner for one owned CLI process group."""

from contextlib import contextmanager
import json
import os
import selectors
import signal
import subprocess
import time

from fixture import Failed, MAX_REPORT

STOP_TIMEOUT = 2
POLL_SECONDS = 0.005
PIPE_CHUNK = 8192
CLEANUP_MARKER = "cleanup-unconfirmed.json"


@contextmanager
def owned_cli_process(evidence, case, command, cwd, stdout, stderr):
    """Record possible nested ownership before creating another process group."""
    marker = evidence / CLEANUP_MARKER
    with marker.open("x", encoding="utf-8") as ownership:
        json.dump(
            {"schema": "exacopy.cli-campaign-cleanup.v1", "case": case, "status": "unconfirmed"},
            ownership,
        )
        ownership.write("\n")
        ownership.flush()
        os.fsync(ownership.fileno())
    directory = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    process = OwnedProcess(command, cwd, stdout, stderr)
    try:
        with process:
            yield process
    finally:
        if process.cleanup_confirmed:
            # An interruption can conservatively retain a marker after cleanup.
            # The marker never disappears before cleanup has been confirmed.
            marker.unlink()


def wait_group_drained(group, timeout=STOP_TIMEOUT):
    """Observe original group absence without signaling after leader reap."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return
        except OSError as error:
            raise Failed("owned CLI group absence could not be observed") from error
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failed("owned CLI process group remained after leader reaping")
        time.sleep(min(POLL_SECONDS, remaining))


class OwnedProcess:
    """Keeps the original leader unreaped until the whole group is fenced."""

    def __init__(self, command, cwd, stdout, stderr):
        self._selector = selectors.DefaultSelector()
        self._exceeded = False
        self._killed = False
        self.returncode = None
        self.cleanup_confirmed = False
        try:
            self._child = subprocess.Popen(
                command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
            )
        except BaseException:
            self._selector.close()
            raise
        self._group = self._child.pid
        try:
            self._check_initial_group()
        except BaseException:
            self._selector.close()
            self._child.stdout.close()
            self._child.stderr.close()
            self._child.kill()
            self._child.wait(timeout=STOP_TIMEOUT)
            raise
        try:
            for stream, destination in ((self._child.stdout, stdout), (self._child.stderr, stderr)):
                self._selector.register(stream, selectors.EVENT_READ, (destination, 0))
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check_initial_group(self):
        try:
            group = os.getpgid(self._child.pid)
        except ProcessLookupError:
            if self.exited():
                # Some systems stop exposing PGID for a zombie. A
                # successful Popen has already confirmed setsid before exec.
                return
            raise
        if group != self._group:
            raise Failed("the owned CLI child is outside its original process group")

    def _event(self, event):
        return os.waitid(os.P_PID, self._child.pid, event | os.WNOHANG | os.WNOWAIT)

    def exited(self):
        result = self._event(os.WEXITED)
        return result is not None and result.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)

    def signal(self, event):
        # The child became session leader before exec and cannot leave
        # that group. Its unreaped PID reserves the PGID through teardown.
        os.killpg(self._group, event)
        if event == signal.SIGKILL:
            self._killed = True

    def confirm_stopped(self, timeout=STOP_TIMEOUT):
        self.signal(signal.SIGSTOP)
        until = time.monotonic() + timeout
        while time.monotonic() < until and not self.exited():
            event = self._event(os.WSTOPPED)
            if event is not None and event.si_code == os.CLD_STOPPED and event.si_status == signal.SIGSTOP:
                return
            self.pump()
        raise Failed("no confirmed group stop from the owned CLI child")

    def wait_for_exit(self, timeout):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if self.exited():
                return
            self.pump()
        raise subprocess.TimeoutExpired(self._child.args, timeout)

    def pump(self, *, draining=False):
        for key, _ in self._selector.select(POLL_SECONDS):
            destination, length = key.data
            data = os.read(key.fd, PIPE_CHUNK)
            if not data:
                self._selector.unregister(key.fileobj)
                continue
            retained = data[:MAX_REPORT - length]
            destination.write(retained)
            length += len(retained)
            self._selector.modify(key.fileobj, selectors.EVENT_READ, (destination, length))
            if len(retained) != len(data):
                self._exceeded = True
        if self._exceeded and not draining:
            raise Failed("compiled CLI output exceeded the retained per-stream limit")

    def close(self):
        # Always kill the validated group before reaping. The leader can have
        # already exited while other group members retain open descriptors.
        try:
            try:
                if not self._killed:
                    self.signal(signal.SIGKILL)
            except ProcessLookupError:
                # The leader is still reserved and no group member remains.
                pass
            until = time.monotonic() + STOP_TIMEOUT
            while self._selector.get_map():
                if time.monotonic() >= until:
                    raise Failed("owned CLI output descriptors did not close after group termination")
                self.pump(draining=True)
        finally:
            self._selector.close()
            self._child.stdout.close()
            self._child.stderr.close()
            self.returncode = self._child.wait(timeout=STOP_TIMEOUT)
        # Pipe EOF and leader exit cannot exclude a pipe-less descendant.
        # The original leader is now reaped. Send no further real signal.
        wait_group_drained(self._group)
        self.cleanup_confirmed = True
        if self._exceeded:
            raise Failed("compiled CLI output exceeded the retained per-stream limit")

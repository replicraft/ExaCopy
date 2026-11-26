"""Owned-child control witnesses without executing the Linux campaign."""

import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

from campaign import cleanup_status
from fixture import Failed, MAX_REPORT
from process import CLEANUP_MARKER, OwnedProcess, owned_cli_process, wait_group_drained

ROOT = Path(__file__).resolve().parent


class ProcessControls(unittest.TestCase):
    def test_exited_leader_does_not_leave_descendant_output_pipes_open(self):
        # The forked child intentionally holds both inherited pipes. It has
        # no escape from the runner's process group and a short backstop.
        output, errors = io.BytesIO(), io.BytesIO()
        launcher = (
            "import os, time\n"
            "read_end, write_end = os.pipe()\n"
            "if os.fork() == 0:\n"
            "    os.close(read_end)\n"
            "    os.write(1, b'descendant started\\n')\n"
            "    os.write(write_end, b'x')\n"
            "    time.sleep(10)\n"
            "else:\n"
            "    os.close(write_end)\n"
            "    os.read(read_end, 1)\n"
            "os._exit(0)\n"
        )
        command = [sys.executable, "-c", launcher]
        with OwnedProcess(command, ROOT, output, errors) as child:
            child.wait_for_exit(2)
            child.pump()
            self.assertEqual(output.getvalue(), b"descendant started\n")
        self.assertEqual(child.returncode, 0)
        self.assertEqual(errors.getvalue(), b"")

    def test_group_stop_must_be_observed_before_kill(self):
        output, errors = io.BytesIO(), io.BytesIO()
        with OwnedProcess([sys.executable, "-c", "import time; time.sleep(10)"], ROOT, output, errors) as child:
            child.confirm_stopped()
            self.assertFalse(child.exited())
            child.signal(signal.SIGKILL)
            child.wait_for_exit(2)
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_log_limit_and_timeout_fence_the_group(self):
        output, errors = io.BytesIO(), io.BytesIO()
        command = [
            sys.executable, "-c",
            f"import os, time; os.write(1, b'x' * {MAX_REPORT + 1}); time.sleep(10)",
        ]
        with self.assertRaisesRegex(Failed, "output exceeded"):
            with OwnedProcess(command, ROOT, output, errors) as child:
                child.wait_for_exit(2)
        self.assertEqual(len(output.getvalue()), MAX_REPORT)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        with self.assertRaises(subprocess.TimeoutExpired):
            with OwnedProcess([sys.executable, "-c", "import time; time.sleep(10)"], ROOT, output, errors) as child:
                child.wait_for_exit(0.01)
        self.assertEqual(child.returncode, -signal.SIGKILL)


    def test_confirmed_cleanup_removes_marker_even_after_bounded_output_failure(self):
        with tempfile.TemporaryDirectory() as scratch:
            evidence = Path(scratch)
            marker = evidence / CLEANUP_MARKER
            command = [
                sys.executable, "-c",
                f"import os, signal; os.write(1, b'x' * {MAX_REPORT + 1}); signal.pause()",
            ]
            with self.assertRaisesRegex(Failed, "output exceeded"):
                with owned_cli_process(evidence, "output", command, ROOT, io.BytesIO(), io.BytesIO()) as child:
                    self.assertEqual(json.loads(marker.read_text())["status"], "unconfirmed")
                    child.wait_for_exit(2)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertFalse(marker.exists())
            summary = {"status": "fail"}
            self.assertEqual(cleanup_status(evidence, summary, 1), 1)

    def test_cleanup_failure_retains_marker_and_blocks_over_ordinary_case_failure(self):
        class Unconfirmed:
            cleanup_confirmed = False

            def __enter__(self):
                return self

            def __exit__(self, *_):
                raise Failed("simulated unconfirmed drain")

        with tempfile.TemporaryDirectory() as scratch:
            evidence = Path(scratch)
            marker = evidence / CLEANUP_MARKER
            with patch("process.OwnedProcess", return_value=Unconfirmed()):
                with self.assertRaisesRegex(Failed, "unconfirmed drain"):
                    with owned_cli_process(evidence, "timeout", [], ROOT, io.BytesIO(), io.BytesIO()):
                        self.assertEqual(json.loads(marker.read_text())["case"], "timeout")
            self.assertTrue(marker.exists())
            summary = {"status": "fail", "reason": "simulated unconfirmed drain"}
            self.assertEqual(cleanup_status(evidence, summary, 1), 77)
            self.assertEqual(summary["status"], "blocked")
            self.assertEqual(summary["prior_reason"], "simulated unconfirmed drain")

    def test_interrupted_supervisor_leaves_pre_spawn_marker_without_summary(self):
        program = (
            "import io, os, signal, sys; from pathlib import Path; import process; "
            "process.OwnedProcess = lambda *_: os.kill(os.getpid(), signal.SIGKILL); "
            "with process.owned_cli_process(Path(sys.argv[1]), 'interrupted', [], "
            "Path.cwd(), io.BytesIO(), io.BytesIO()): pass"
        )
        prefix, control = program.rsplit("; with ", 1)
        with tempfile.TemporaryDirectory() as scratch:
            evidence = Path(scratch)
            completed = subprocess.run(
                [sys.executable, "-B", "-c", prefix + "\nwith " + control, scratch],
                cwd=ROOT, timeout=2, capture_output=True,
            )
            self.assertEqual(completed.returncode, -signal.SIGKILL, completed.stderr)
            marker = evidence / CLEANUP_MARKER
            self.assertEqual(json.loads(marker.read_text())["case"], "interrupted")
            self.assertFalse((evidence / "summary.json").exists())


    def test_group_drain_uses_only_lookup_after_reap(self):
        with patch("process.os.killpg", side_effect=[None, ProcessLookupError]) as probe:
            wait_group_drained(123)
        self.assertEqual(probe.call_args_list, [call(123, 0), call(123, 0)])
        with patch("process.os.killpg", return_value=None):
            with self.assertRaisesRegex(Failed, "remained after leader reaping"):
                wait_group_drained(123, timeout=0)
        with patch("process.os.killpg", side_effect=PermissionError):
            with self.assertRaisesRegex(Failed, "absence could not be observed"):
                wait_group_drained(123)

    def test_pipe_eof_and_leader_reap_do_not_clear_pending_group_marker(self):
        real_killpg = os.killpg

        def group_still_present(group, event):
            if event != 0:
                real_killpg(group, event)

        with tempfile.TemporaryDirectory() as scratch:
            evidence = Path(scratch)
            command = [sys.executable, "-c", "import time; time.sleep(10)"]
            with patch("process.os.killpg", side_effect=group_still_present):
                with self.assertRaisesRegex(Failed, "remained after leader reaping"):
                    with owned_cli_process(evidence, "pipe-eof", command, ROOT, io.BytesIO(), io.BytesIO()) as child:
                        child.signal(signal.SIGKILL)
                        child.wait_for_exit(2)
            self.assertEqual(child.returncode, -signal.SIGKILL)
            self.assertTrue((evidence / CLEANUP_MARKER).exists())


if __name__ == "__main__":
    unittest.main()

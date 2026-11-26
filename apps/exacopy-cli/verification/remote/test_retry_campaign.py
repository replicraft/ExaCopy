"""Independent fixture packet tests. The real native download has its own campaign."""

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import selectors
import shutil
import struct
import subprocess
import tempfile
import unittest

from fixture import Failed, check_held
from retry_campaign import (
    Event, PreviousStage, SOURCE_BYTES, Trace, WINDOW, one, parse_trace, peer_pass, read_terminal,
    release_new, require_closed,
)


def string(data):
    return struct.pack(">I", len(data)) + data


class FixturePeerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name).resolve()
        self.trace = root / "retry-state" / "events"
        self.control = root / "retry-control" / "release-redial"
        for parent in (self.trace.parent, self.control.parent, root / "retry-input"):
            parent.mkdir()
        self.trace.touch()
        self.bytes = bytes(range(256)) * (SOURCE_BYTES // 256)
        for name in ("redial", "expired"):
            source = root / "retry-input" / name
            source.write_bytes(self.bytes)
            source.chmod(0o444)
        self.binary = root / "peer"
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("no local C compiler")
        source = Path(__file__).with_name("retry_sftp_peer.c")
        subprocess.run(
            [cc, "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror",
             f'-DEXACOPY_FIXTURE_ROOT="{root}"', source, "-o", self.binary],
            check=True, timeout=12,
        )

    def peer(self):
        child = subprocess.Popen(
            [self.binary, "-c", "exacopy-fixture-sftp-v1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
        )

        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            child.stdin.close()
            child.stdout.close()

        self.addCleanup(cleanup)
        return child

    def send(self, child, op, reference, body=b""):
        frame = bytes([op]) + struct.pack(">I", reference) + body
        child.stdin.write(struct.pack(">I", len(frame)) + frame)

    def reply(self, child):
        with selectors.DefaultSelector() as watch:
            watch.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(watch.select(2), "fixture response timed out")
        size = struct.unpack(">I", child.stdout.read(4))[0]
        self.assertLessEqual(size, 64 * 1024)
        data = bytearray()
        while len(data) < size:
            fragment = child.stdout.read(size - len(data))
            self.assertTrue(fragment, "short fixture response")
            data.extend(fragment)
        return bytes(data)

    def still_held(self, child):
        with selectors.DefaultSelector() as watch:
            watch.register(child.stdout, selectors.EVENT_READ)
            self.assertFalse(watch.select(0.08), "fixture returned a withheld reply")

    def login_sftp(self, child, name, flags=1):
        self.send(child, 1, 3)
        self.assertEqual(self.reply(child), b"\x02\x00\x00\x00\x03")
        path = string(f"/retry-input/{name}".encode("ascii"))
        self.send(child, 3, 1, path + struct.pack(">II", flags, 0))
        if flags == 1:
            self.assertEqual(self.reply(child), b"\x66\x00\x00\x00\x01" + string(b"f"))
        return path

    def test_timeout_closure_and_second_zero_offset_are_separate_observations(self):
        first = self.peer()
        self.login_sftp(first, "redial")
        self.send(first, 5, 2, string(b"f") + struct.pack(">QI", 0, 32768))
        self.assertEqual(self.reply(first)[9:], self.bytes[:32768])
        self.send(first, 5, 3, string(b"f") + struct.pack(">QI", WINDOW, 32768))
        self.still_held(first)
        first.stdin.close()
        self.assertEqual(first.wait(timeout=2), 0)

        second = self.peer()
        path = self.login_sftp(second, "redial")
        self.send(second, 5, 2, string(b"f") + struct.pack(">QI", 0, 32768))
        self.still_held(second)
        self.control.touch()
        self.assertEqual(self.reply(second)[9:], self.bytes[:32768])
        self.send(second, 5, 3, string(b"f") + struct.pack(">QI", SOURCE_BYTES, 1))
        self.assertEqual(self.reply(second)[:9], bytes([101]) + struct.pack(">II", 3, 1))
        self.send(second, 8, 4, string(b"f"))
        self.assertEqual(self.reply(second)[0], 105)
        self.send(second, 4, 5, string(b"f"))
        self.assertEqual(self.reply(second)[0], 101)
        self.send(second, 7, 6, path)
        self.assertEqual(self.reply(second)[0], 105)
        second.stdin.close()
        self.assertEqual(second.wait(timeout=2), 0)

        rows = parse_trace(self.trace.read_bytes())
        self.assertEqual(one(rows, "redial", 1, "transport-closed").offset, WINDOW)
        self.assertEqual(one(rows, "redial", 2, "new-zero-held").offset, 0)
        self.assertEqual([row.kind for row in peer_pass(rows, "redial", [1, 2]) if row.attempt == 2][-4:],
                         ["eof", "fstat", "close", "lstat"])

    def test_write_flag_is_refused_and_no_session_slot_is_spent(self):
        child = self.peer()
        self.login_sftp(child, "expired", flags=2)
        self.assertEqual(child.wait(timeout=2), 2)
        self.assertEqual(self.trace.read_bytes(), b"")

    def test_arbitrary_shell_command_is_refused(self):
        result = subprocess.run([self.binary, "-c", "anything-else"], check=False, timeout=2)
        self.assertEqual(result.returncode, 2)


class OracleTests(unittest.TestCase):
    def test_terminal_evidence_precedes_missing_session_and_excludes_private_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            stdout, observed = root / "budget.stdout", root / "budget.terminal.json"
            report = {
                "schema": "exacopy.cli.remote_download", "schema_version": "1.0",
                "result": "failed", "publication": "not_published",
                "error": {"code": "E_AUTHORIZATION", "job_directory": "/private/fixture"},
            }
            stdout.write_text(json.dumps(report))
            self.assertEqual(read_terminal(stdout, observed, 8, 41.3299), report)
            trace = [Event("budget", 1, kind, 0, 1, 1)
                     for kind in ("open", "timeout-held", "transport-closed")]
            for kind, reason in (("open", "no SFTP open"), ("timeout-held", "no held READ"),
                                 ("transport-closed", "no closure observed")):
                with self.subTest(kind=kind), self.assertRaisesRegex(Failed, reason + ".*session 2"):
                    require_closed(trace, "budget", (1, 2))
                trace.append(Event("budget", 2, kind, 0, 1, 2))
            require_closed(trace, "budget", (1, 2))
            self.assertEqual(json.loads(observed.read_bytes()), {
                "exit_status": 8, "elapsed_seconds": 41.33, "report_schema_valid": True,
                "result": "failed", "publication": "not_published", "error_code": "E_AUTHORIZATION",
            })

    def test_invalid_terminal_report_still_records_exit_without_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            stdout, observed = root / "budget.stdout", root / "budget.terminal.json"
            stdout.write_text("private non-JSON output")
            with self.assertRaises(ValueError):
                read_terminal(stdout, observed, 2, 0.3)
            self.assertEqual(json.loads(observed.read_bytes()), {
                "exit_status": 2, "elapsed_seconds": 0.3, "report_schema_valid": False,
                "result": None, "publication": None, "error_code": None,
            })

    def test_trace_failure_retains_last_validated_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / "trace"
            path.touch()
            trace = Trace(path)
            validated = b"redial 1 open 0 0 22\n"
            path.write_bytes(validated)
            self.assertEqual(trace.snapshot(), [Event("redial", 1, "open", 0, 0, 22)])
            with path.open("ab") as output:
                output.write(b"redial 1 unexpected 0 0 23\n")
            with self.assertRaises(Failed):
                trace.snapshot()
            self.assertEqual(trace.prior, validated)

    def test_fresh_stage_descriptor_detects_replacement_after_publication(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as observe:
            root = Path(temp).resolve()
            stages = root / "stage"
            stages.mkdir(mode=0o700)
            old = stages / ("capture-" + "aaaabbbb-1234-5000-a000-000000000001")
            fresh = stages / ("capture-" + "aaaabbbb-1234-5000-a000-000000000002")
            old.write_bytes(b"old")
            fresh.touch()
            held = observe.enter_context(old.open("rb"))
            retained = PreviousStage(root, old, held, old.stat(), hashlib.sha256(b"old").hexdigest())
            target = root / "publication"
            args = SimpleNamespace(release_path=root / "release-redial")
            fresh_file, stamp = release_new(observe, args, retained, target)
            self.assertEqual(stamp, (fresh.stat().st_dev, fresh.stat().st_ino))
            fresh.write_bytes(b"new content")
            fresh.rename(target)
            check_held(target, fresh_file, target.stat())
            target.unlink()
            target.write_bytes(b"new content")
            with self.assertRaises(Failed):
                check_held(target, fresh_file, target.stat())

    def test_partial_unknown_and_extra_trace_records_are_rejected(self):
        for line in (b"unfinished", b"redial 1 sneaky 0 0 123\n", b"redial 9 read 0 8 32\n"):
            with self.subTest(line=line), self.assertRaises(Failed):
                parse_trace(line)
        with self.assertRaises(Failed):
            peer_pass([Event("redial", 1, "open", 0, 0, 1),
                       Event("redial", 1, "read", WINDOW, 1, 2)], "redial", [1])
        with self.assertRaises(Failed):
            peer_pass([Event("redial", 2, "open", 0, 0, 1)], "redial", [1])


if __name__ == "__main__":
    unittest.main()

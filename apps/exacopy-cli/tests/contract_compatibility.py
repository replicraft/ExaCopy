#!/usr/bin/env python3
"""Exercise retained Linux jobs in both directions between two actual CLI builds."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile

PROFILE = "profile"
SEGMENT = "journal/00000000000000000001.exajnl"
RECEIPT = "receipts/receipt.cbor"
PAYLOAD = b"\x00ExaCopy contract compatibility\xff\n"
INCUMBENT = b"unrelated incumbent"
PUBLISH_INTENT = 7
FRAME_OVERHEAD = 92
RANGE_LIMIT = 64 * 1024 * 1024


def invoke(binary, root, *args, expected=0):
    result = subprocess.run(
        [binary, *args], cwd=root, capture_output=True, timeout=60, check=False
    )
    assert result.returncode == expected, (
        f"{args[0]}: expected exit {expected}, got {result.returncode}. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert not result.stderr, result.stderr
    return result.stdout


def recover(binary, root, action, job, *, expected=0, profile=PROFILE):
    arguments = [job.name, "--profile", profile, "--format", "json"]
    if action in ("retry", "resume"):
        arguments.extend(("--source-root", "."))
    report = json.loads(
        invoke(binary, root, "recover", action, *arguments, expected=expected)
    )
    assert report["schema"] == "exacopy.local_recovery_inspection", report
    assert report["schema_version"] == "1.0", report
    return report


def snapshot(root):
    observed = {}
    for path in root.rglob("*"):
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        digest = None
        if stat.S_ISREG(metadata.st_mode):
            with path.open("rb") as contents:
                digest = hashlib.file_digest(contents, "sha256").hexdigest()
        observed[path.relative_to(root)] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            digest,
        )
    return observed


def assert_unchanged(root, before, label):
    after = snapshot(root)
    changed = [
        str(path)
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    ]
    assert not changed, f"{label} changed paths: {sorted(changed)}"


def prefix_through_intent(data):
    offset = 0
    while offset < len(data):
        magic, version, kind, length = struct.unpack_from("<8sHHI", data, offset)
        assert magic == b"EXAJNL01" and version == 1, (magic, version)
        offset += FRAME_OVERHEAD + length
        assert offset <= len(data), "frame exceeds captured journal"
        if kind == PUBLISH_INTENT:
            return data[:offset]
    raise AssertionError("completed journal lacks publication intent")


def assert_complete(report):
    assert report["result"] == "inspected", report
    assert report["disposition"] == "complete", report
    assert report["journal_tail"] == "clean", report
    assert int(report["journal_sequence"]) > 0, report


def refusal(binary, root, job, action, *, code, message=None, profile=PROFILE, expected=5):
    report = recover(binary, root, action, job, expected=expected, profile=profile)
    assert report["result"] == "failed", report
    assert report["code"] == code, report
    if message is not None:
        assert message in report["message"], report


def test_unsupported(root, job, binaries, versions):
    for label, path, supported_prefix, offset, replacement, diagnostic in versions:
        original = path.read_bytes()
        assert original.startswith(supported_prefix), f"unexpected {label} encoding"
        synthetic = original[:offset] + replacement + original[offset + len(replacement):]
        assert original != synthetic, label
        path.write_bytes(synthetic)
        try:
            before = snapshot(root)
            for binary in binaries:
                for action in ("inspect", "finish", "resume", "retry"):
                    refusal(binary, root, job, action, code="E_INTEGRITY", message=diagnostic)
                    assert_unchanged(root, before, f"{label} {action}")
        finally:
            path.write_bytes(original)
        for binary in binaries:
            assert_complete(recover(binary, root, "inspect", job))
        print(f"PASS {label}: both readers, four entry points, protected bytes and identities")


def test_direction(writer, reader, scratch, label, *, future_controls=False):
    with tempfile.TemporaryDirectory(prefix=f"{label}-", dir=scratch) as directory:
        root = Path(directory)
        source = root / "source"
        with source.open("wb") as file:
            file.write(PAYLOAD)
            file.seek(RANGE_LIMIT)
            file.write(PAYLOAD)
        (root / "incumbent").write_bytes(INCUMBENT)
        invoke(writer, root, "profile", "init", PROFILE)
        initial = snapshot(root)
        report = json.loads(
            invoke(
                writer, root, "copy", "source", "target",
                "--profile", PROFILE, "--format", "json",
            )
        )
        assert (report["schema"], report["schema_version"]) == ("exacopy.cli.copy", "1.0")
        assert report["result"] == "published", report
        target = root / "target"
        assert target.read_bytes() == source.read_bytes()
        target_inode = target.stat().st_ino
        job = root / report["receipt"]["job_directory"]
        pages = sorted((job / "checkpoints").glob("range-*.cbor"))
        assert pages, "fixture must include a journal-referenced range page"
        before = snapshot(root)
        for path, observed in initial.items():
            assert before[path] == observed, f"copy changed {path}"
        own_report = recover(writer, root, "inspect", job)
        assert_complete(own_report)
        assert recover(reader, root, "inspect", job) == own_report
        assert recover(reader, root, "finish", job) == own_report
        assert_unchanged(root, before, "compatible inspection and repeated finish")
        print(f"PASS {label}: complete job (profile, owner, plan, journal, range pages, receipt)")

        journal = job / SEGMENT
        receipt = job / RECEIPT
        if future_controls:
            versions = [
                (
                    "future journal version", journal, b"EXAJNL01\x01\x00",
                    8, b"\x02", "UnsupportedVersion(2)",
                ),
                (
                    "future plan major", job / "plan.cbor", b"\x85\x82\x01\x00",
                    2, b"\x02", "unsupported local copy plan version",
                ),
                (
                    "unknown receipt feature", receipt, b"\xab\x00\x83\x01\x00\x00",
                    5, b"\x01", "unsupported copy receipt version or features",
                ),
                (
                    "future receipt major", receipt, b"\xab\x00\x83\x01\x00\x00",
                    3, b"\x02", "unsupported copy receipt version or features",
                ),
                (
                    "future range page version", pages[0], b"\xa7\x00\x01",
                    2, b"\x02", "unsupported verification evidence",
                ),
            ]
            test_unsupported(root, job, (writer, reader), versions)
            invoke(writer, root, "profile", "init", "foreign-profile")
            before = snapshot(root)
            for binary in (writer, reader):
                for action in ("inspect", "finish", "resume", "retry"):
                    refusal(
                        binary, root, job, action, code="E_PROFILE_AUTHORIZATION",
                        profile="foreign-profile", expected=8,
                    )
                    assert_unchanged(root, before, f"wrong profile {action}")
            print("PASS foreign profiles: both readers and four entry points")
            seed = root / PROFILE / "owner.seed"
            original_seed = seed.read_bytes()
            assert len(original_seed) == 32, "unexpected profile seed length"
            seed.write_bytes(original_seed + b"\x00")
            try:
                before = snapshot(root)
                for binary in (writer, reader):
                    for action in ("inspect", "finish", "resume", "retry"):
                        refusal(
                            binary, root, job, action,
                            code="E_PROFILE_AUTHORIZATION", expected=8,
                        )
                        assert_unchanged(root, before, f"unknown profile shape {action}")
            finally:
                seed.write_bytes(original_seed)
            print("PASS unknown profile shape: oversized disposable seed was preserved")

        # Model interruption immediately after public rename by retaining the
        # authentic intent prefix and target, then removing the later receipt.
        prefix = prefix_through_intent(journal.read_bytes())
        journal.write_bytes(prefix)
        receipt.unlink()
        before = snapshot(root)
        interrupted = recover(reader, root, "inspect", job, expected=9)
        assert interrupted["disposition"] == "published_needs_barriers", interrupted
        assert_unchanged(root, before, "interrupted inspection")
        recovered = recover(reader, root, "finish", job)
        assert_complete(recovered)
        assert target.stat().st_ino == target_inode
        assert journal.read_bytes().startswith(prefix)
        assert target.read_bytes() == source.read_bytes()
        after = snapshot(root)
        changed = {journal.relative_to(root), receipt.relative_to(root)}
        assert {path: value for path, value in before.items() if path not in changed} == {
            path: value for path, value in after.items() if path not in changed
        }, "recovery changed protected artifacts"
        assert recover(writer, root, "inspect", job) == recovered
        assert recover(writer, root, "finish", job) == recovered
        assert_unchanged(root, after, "original reader after cross-revision recovery")
        print(f"PASS {label}: finish from retained publish intent and idempotent reopen")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("scratch", type=Path, help="directory on the Linux filesystem under test")
    args = parser.parse_args()
    assert sys.platform == "linux", "this test requires the Linux copy executor"
    if sys.flags.optimize:
        parser.error("run without Python's -O so the oracles execute")
    os.umask(0o077)
    old, new = args.old.resolve(strict=True), args.new.resolve(strict=True)
    assert not old.samefile(new), "supply two independent CLI builds"
    assert old.read_bytes() != new.read_bytes(), "supply distinguishable CLI builds"
    test_direction(old, new, args.scratch, "upgrade")
    test_direction(new, old, args.scratch, "downgrade", future_controls=True)


if __name__ == "__main__":
    main()

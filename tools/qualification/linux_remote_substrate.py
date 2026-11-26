#!/usr/bin/env python3
"""Run the destination-only native kill diagnostic and retain a nonqualifying artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

from linux_remote_source import source_identity
from native_supervision import CleanupUnconfirmed, file_digest, interrupted, logged_command

REPO = Path(__file__).resolve().parents[2]
SELECTOR = (
    "linux::process_crash::remote_destination::tests::campaign::"
    "destination_substrate_preserves_bytes_at_each_native_process_cut"
)
EXPECTED = ("private-created", "data-synced", "closed-readback", "published-and-synced")
PASSED = re.compile(rb"^EXACOPY_REMOTE_SUBSTRATE_PASS ([a-z-]+)$", re.MULTILINE)
PARENT_MARKER = re.compile(rb"^EXACOPY_REMOTE_SUBSTRATE_PARENT(?:[ \t]|$)", re.MULTILINE)
PARENT = re.compile(
    rb"^EXACOPY_REMOTE_SUBSTRATE_PARENT ([1-9][0-9]{0,19}) ([1-9][0-9]{0,19}) "
    rb"([0-9a-f]{32}) ([1-9][0-9]{0,19}) ([1-9][0-9]{0,19}) ([1-9][0-9]{0,19})$",
    re.MULTILINE,
)
PARENT_FIELDS = ("device", "inode", "boot_id_hex", "mount_namespace", "mount_id", "unique_mount")
MAX_LOG_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 600
SOURCE_INPUTS = (
    "tools/qualification/linux_remote_substrate.py",
    "tools/qualification/linux_remote_source.py",
    "tools/qualification/native_supervision.py",
    "crates/interfaces/exacopy-endpoint/src/linux_remote_qualification.rs",
    "crates/platform/exacopy-platform/src/linux/mount_observation.rs",
    "crates/platform/exacopy-platform/src/linux/process_crash/remote_destination.rs",
    "crates/platform/exacopy-platform/src/linux/process_crash/remote_destination/tests/campaign.rs",
)


def run(destination: Path, output: Path, *, environment=None) -> int:
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    recorder = {
        "schema": "ExaCopy/linux-remote-destination-substrate-diagnostic/v1",
        "qualifies_remote_download": False,
        "platform": platform.system(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "cases": [],
    }
    log = output / "native.log"
    result = 77
    cleanup = None
    if sys.platform != "linux":
        recorder["outcome"] = "blocked_non_linux"
        log.write_bytes(b"Native Linux is required for the destination diagnostic.\n")
    elif not shutil.which("cargo"):
        recorder["outcome"] = "blocked_no_cargo"
        log.write_bytes(b"Cargo is required for the locked native fixture.\n")
    else:
        try:
            root = destination.absolute()
            if root != root.resolve(strict=True):
                raise ValueError("the diagnostic root must resolve without symlinks")
            details = root.stat()
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
                raise ValueError("the diagnostic root must be an owned directory")
            env = dict(os.environ if environment is None else environment,
                       CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true")
            command = [
                "cargo", "+1.100.0", "test", "--offline", "--locked", "-p", "exacopy-platform", "--lib",
                SELECTOR, "--", "--exact", "--ignored", "--nocapture",
            ]
            before = source_identity(REPO)
            recorder["source_before"] = before
            recorder["revision"] = before["revision"]
            recorder["lock_sha256"] = before["lock_sha256"]
            recorder["source_sha256"] = {name: file_digest(REPO / name) for name in SOURCE_INPUTS}
            recorder["command"] = command
            disposable = Path(tempfile.mkdtemp(prefix=".exacopy-substrate-", dir=root))
            try:
                env["TMPDIR"] = os.fspath(disposable)
                env["EXACOPY_REMOTE_SUBSTRATE_PARENT"] = os.fspath(root)
                default_target = disposable / "cargo-target"
                cargo_target = (REPO / env.get("CARGO_TARGET_DIR", os.fspath(default_target))).resolve()
                if cargo_target.is_relative_to(REPO):
                    raise ValueError("native substrate build target must be outside the source checkout")
                env["CARGO_TARGET_DIR"] = os.fspath(cargo_target)
                process = logged_command(
                    command, log, TIMEOUT_SECONDS, cwd=REPO, env=env, output_limit=MAX_LOG_BYTES,
                )
            except CleanupUnconfirmed:
                # The group may still hold its process-cut fixtures or Cargo work.
                raise
            except BaseException:
                shutil.rmtree(disposable)
                raise
            else:
                shutil.rmtree(disposable)
            after = source_identity(REPO)
            recorder["source_after"] = after
            if before != after:
                raise ValueError("source changed during the native substrate campaign")
            cases, parent = read_markers(log)
            recorder["cases"] = list(cases)
            recorder["process_exit"] = process.exit_status
            recorder["process_status"] = process.status
            result = int(not process.passed() or cases != EXPECTED or parent is None)
            if parent is not None:
                recorder["destination_parent"] = parent
            if process.status != "exited":
                recorder["outcome"] = f"blocked_{process.status.replace('-', '_')}"
                result = 77
            else:
                recorder["outcome"] = "passed_native_substrate" if result == 0 else "failed_native_substrate"
        except CleanupUnconfirmed as error:
            recorder["outcome"] = "blocked_cleanup_unconfirmed"
            cleanup = error
        except KeyboardInterrupt:
            recorder["outcome"] = "blocked_interrupted"
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            recorder["outcome"] = "blocked_fixture_setup"
            recorder["reason"] = str(error) if type(error) is ValueError else type(error).__name__
            if not log.exists():
                log.write_text(recorder["reason"] + "\n")
    try:
        recorder["log_sha256"] = file_digest(log) if log.exists() else None
        with (output / "result.json").open("x") as manifest:
            json.dump(recorder, manifest, indent=2, sort_keys=True)
            manifest.write("\n")
    finally:
        if cleanup is not None:
            raise cleanup
    return result


def read_markers(log: Path) -> tuple[tuple[str, ...], dict[str, str] | None]:
    with log.open("rb") as source:
        raw = source.read(MAX_LOG_BYTES + 1)
    return parse_markers(raw)


def parse_markers(raw: bytes) -> tuple[tuple[str, ...], dict[str, str] | None]:
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError("native substrate log exceeds the input bound")
    cases = tuple(marker[1].decode("ascii") for marker in PASSED.finditer(raw))
    candidates = PARENT_MARKER.finditer(raw)
    first = next(candidates, None)
    parent = None
    if first is not None and next(candidates, None) is None:
        exact = PARENT.match(raw, first.start())
        if exact is None:
            return cases, None
        fields = [item.decode("ascii") for item in exact.groups()]
        if all(int(value) < 2**64 for key, value in zip(PARENT_FIELDS, fields)
               if key != "boot_id_hex"):
            parent = dict(zip(PARENT_FIELDS, fields, strict=True))
    return cases, parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    arguments = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        return run(arguments.destination, arguments.evidence)
    except CleanupUnconfirmed:
        print("Native substrate blocked: owned group cleanup unconfirmed; fixture retained.", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())

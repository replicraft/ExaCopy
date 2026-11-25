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
from typing import BinaryIO

REPO = Path(__file__).resolve().parents[2]
SELECTOR = (
    "linux::process_crash::remote_destination::tests::campaign::"
    "destination_substrate_preserves_bytes_at_each_native_process_cut"
)
EXPECTED = ("private-created", "data-synced", "closed-readback", "published-and-synced")
PASSED = re.compile(rb"^EXACOPY_REMOTE_SUBSTRATE_PASS ([a-z-]+)$", re.MULTILINE)
TIMEOUT_SECONDS = 600
SOURCE_INPUTS = (
    "tools/qualification/linux_remote_substrate.py",
    "crates/interfaces/exacopy-endpoint/src/linux_remote_qualification.rs",
    "crates/platform/exacopy-platform/src/linux/mount_observation.rs",
    "crates/platform/exacopy-platform/src/linux/process_crash/remote_destination.rs",
    "crates/platform/exacopy-platform/src/linux/process_crash/remote_destination/tests/campaign.rs",
)


def run(destination: Path, output: Path) -> int:
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
            env = dict(os.environ, CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true")
            command = [
                "cargo", "test", "--offline", "--locked", "-p", "exacopy-platform", "--lib",
                SELECTOR, "--", "--exact", "--ignored", "--nocapture",
            ]
            recorder["revision"] = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=REPO, timeout=10, text=True
            ).strip()
            recorder["lock_sha256"] = hash_file(REPO / "Cargo.lock")
            recorder["source_sha256"] = {name: hash_file(REPO / name) for name in SOURCE_INPUTS}
            recorder["command"] = command
            with tempfile.TemporaryDirectory(prefix=".exacopy-substrate-", dir=root) as disposable:
                env["TMPDIR"] = disposable
                with log.open("xb") as output_log:
                    exit_code = run_owned_group(command, env, output_log)
            cases = read_cut_markers(log)
            recorder["cases"] = list(cases)
            recorder["process_exit"] = exit_code
            result = int(exit_code != 0 or cases != EXPECTED)
            recorder["outcome"] = "passed_native_substrate" if result == 0 else "failed_native_substrate"
        except subprocess.TimeoutExpired:
            recorder["outcome"] = "blocked_timeout"
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            recorder["outcome"] = "blocked_fixture_setup"
            if not log.exists():
                log.write_text(f"{type(error).__name__}: {error}\n")
    recorder["log_sha256"] = hash_file(log) if log.exists() else None
    with (output / "result.json").open("x") as manifest:
        json.dump(recorder, manifest, indent=2, sort_keys=True)
        manifest.write("\n")
    return result


def hash_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run_owned_group(command: list[str], env: dict[str, str], output: BinaryIO) -> int:
    with subprocess.Popen(
        command, cwd=REPO, env=env, stdout=output, stderr=subprocess.STDOUT,
        start_new_session=True,
    ) as process:
        try:
            return process.wait(timeout=TIMEOUT_SECONDS)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def read_cut_markers(log: Path) -> tuple[str, ...]:
    cases = []
    with log.open("rb") as source:
        for line in source:
            marker = PASSED.fullmatch(line.rstrip(b"\n"))
            if marker:
                cases.append(marker[1].decode("ascii"))
                if len(cases) > len(EXPECTED):
                    break
    return tuple(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    arguments = parser.parse_args()
    return run(arguments.destination, arguments.evidence)


if __name__ == "__main__":
    raise SystemExit(main())

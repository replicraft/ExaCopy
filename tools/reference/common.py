"""Shared scaffolding for isolated compatibility and performance evidence."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MACOS = platform.system() == "Darwin"
MACOS_ACL_FIXTURE = ROOT / "fixtures/macos/empty_acl.c"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def capture(args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_fixture(path, size, seed, *, offset=None, sparse=False):
    """Generate SHAKE-256 content in bounded blocks, or a hole with one changed byte."""
    with path.open("xb") as stream:
        remaining = size
        block = 0
        while remaining and not sparse:
            count = min(remaining, 1 << 20)
            data = hashlib.shake_256(f"exacopy-reference-v1:{seed}:{block}".encode()).digest(count)
            stream.write(data)
            remaining -= count
            block += 1
        if sparse:
            stream.truncate(size)
    path.chmod(0o600)
    if offset is not None:
        with path.open("r+b") as stream:
            stream.seek(offset)
            changed = stream.read(1)[0] ^ 1
            stream.seek(offset)
            stream.write(bytes([changed]))
    os.utime(path, ns=(1_700_000_000_000_000_000,) * 2)


def observation(path):
    before = path.stat()
    return {
        "identity": (before.st_dev, before.st_ino),
        "length": before.st_size,
        "mode": before.st_mode,
        "links": before.st_nlink,
        "mtime_ns": before.st_mtime_ns,
        "sha256": digest(path),
    }


def filesystem_type(root):
    if MACOS:
        return "apfs" if len(capture(["df", "-T", "apfs", root]).splitlines()) == 2 else "unknown"
    return capture(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", root])


def prepare(root):
    root.mkdir(mode=0o700)
    if MACOS:
        require(filesystem_type(root) == "apfs" and os.getuid() != 0, "managed APFS requires non-root and APFS")
        helper = root.parent / "empty-acl"
        if not helper.exists():
            subprocess.run([
                "cc", "-Wall", "-Wextra", "-Werror",
                MACOS_ACL_FIXTURE, "-o", helper,
            ], check=True)
        subprocess.run([helper, root], check=True)
    return root


def diff_command(binary, left, right, workers):
    command = [binary, "diff", left, right, "--compare", "bytes", "--workers", str(workers), "--format", "json"]
    if MACOS:
        command.append("--managed-macos")
    return command


def sample(command):
    # Files avoid pipe-buffer deadlocks while wait4 collects per-process usage.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        start = time.perf_counter_ns()
        with subprocess.Popen(command, stdout=out, stderr=err) as process:
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.perf_counter_ns() - start
        out.seek(0)
        err.seek(0)
        return {
            "exit_code": process.returncode,
            "stdout": out.read().decode(errors="replace").strip(),
            "stderr": err.read().decode(errors="replace").strip(),
            "elapsed_ns": elapsed,
            "user_cpu_ns": round(usage.ru_utime * 1e9),
            "system_cpu_ns": round(usage.ru_stime * 1e9),
            "peak_rss_bytes": usage.ru_maxrss * (1 if MACOS else 1024),
        }


def check_diff(run, left_bytes, right_bytes, offset=None):
    same = left_bytes == right_bytes and offset is None
    require(run["exit_code"] == int(not same), f"unexpected diff exit: {run}")
    report = json.loads(run["stdout"])
    require((report["schema"], report["schema_version"], report["relation"], report["complete"], report["consistency"])
            == ("exacopy.cli.diff", "1.0", "bytes", True, "live_observed"), f"unexpected report: {report}")
    if same:
        require(report["result"] == "equal" and report["length"] == str(left_bytes), f"incorrect equality: {report}")
    else:
        expected = ({"kind": "length", "left": str(left_bytes), "right": str(right_bytes)}
                    if left_bytes != right_bytes else {"kind": "first_byte", "offset": str(offset)})
        require(report["result"] == "different" and report["difference"] == expected, f"incorrect witness: {report}")
    return report


def build_record(binary, revision, profile, scratch):
    if revision is None:
        revision = capture(["git", "rev-parse", "HEAD"])
        status = capture(["git", "status", "--short", "--",
                          "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates"])
        require(not status, f"archive or clean production sources before measuring: {status}")
    lock = ROOT / "Cargo.lock"
    dependencies = tomllib.loads(lock.read_text())["package"]
    return {
        "source_revision": revision,
        "build_profile": profile,
        "exacopy_binary_sha256": digest(binary),
        "cargo_lock_sha256": digest(lock),
        "workspace_lock_dependencies": [f"{p['name']} {p['version']}" for p in dependencies if "source" in p],
        "rustc": capture(["rustc", "-Vv"]),
        "cargo": capture(["cargo", "--version"]),
        "platform": {"os": platform.system(), "kernel": platform.release(), "machine": platform.machine(),
                     "version": platform.mac_ver()[0] if MACOS else platform.freedesktop_os_release()["PRETTY_NAME"],
                     "filesystem": filesystem_type(scratch), "python": platform.python_version()},
    }

"""Own exact-checkout, compiler and private native executable provenance."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tomllib

from fixture import ROOT, TARGET, TOOLCHAIN, UNIT_OWNERS

GATE_SECONDS = 900
PROBE_SECONDS = 20
PREFIX = "linux::sync_preview::"
HASH_SOURCE = ROOT / "crates/formats/exacopy-manifest/verification/manifest"
C_INPUTS = ("blake3.c", "blake3.h", "blake3_impl.h", "blake3_portable.c", "blake3_dispatch.c")


def digest(path):
    with path.open("rb", buffering=0) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(evidence, name, args, *, env=None, timeout=PROBE_SECONDS):
    args = [os.fspath(part) for part in args]
    (evidence / f"{name}.argv.json").write_text(json.dumps(args) + "\n", encoding="utf-8")
    try:
        process = subprocess.Popen(
            args, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError:
        retain(evidence, name, b"", b"command unavailable\n", 127)
        raise
    with process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop(process)
            stdout, stderr = process.communicate(timeout=PROBE_SECONDS)
            retain(evidence, name, stdout, stderr + b"\nfixture command timed out\n", 124)
            raise
        except BaseException:
            stop(process)
            raise
    retain(evidence, name, stdout, stderr, process.returncode)
    if process.returncode:
        raise RuntimeError(f"{name} returned {process.returncode}")
    return stdout.decode("utf-8")


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def retain(evidence, label, stdout, stderr, code):
    (evidence / f"{label}.stdout").write_bytes(stdout)
    (evidence / f"{label}.stderr").write_bytes(stderr)
    (evidence / f"{label}.exit").write_text(f"{code}\n", encoding="ascii")


def clean_revision(revision, evidence, phase):
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("expected an exact selected Git revision")
    head = command(evidence, f"revision-{phase}", ["git", "rev-parse", "HEAD"]).strip()
    dirty = command(evidence, f"status-{phase}", ["git", "status", "--porcelain"])
    if revision != head or dirty:
        raise ValueError("qualification requires the exact selected clean Git revision")


def private_build_environment(work):
    overrides = (
        "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTFLAGS",
    )
    if any(os.environ.get(name) for name in overrides):
        raise ValueError("native qualification requires the pinned compiler without overrides")
    # Cargo 1.100 may put libtest executables in its build-dir. Keep both
    # layouts beneath the same exclusive target so admission can verify them.
    target = str(work / "target")
    return {
        **os.environ, "CARGO_TARGET_DIR": target,
        "CARGO_BUILD_BUILD_DIR": target, "TMPDIR": str(work),
        "LC_ALL": "C", "CARGO_TERM_COLOR": "never",
    }


def check_toolchain(evidence):
    version = command(evidence, "rustc", ["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
    if f"host: {TARGET}" not in version or f"release: {TOOLCHAIN}" not in version:
        raise ValueError("unexpected native compiler target or release")


def private_executable(path, target_dir):
    if (
        not path.is_absolute() or path.resolve() != path or not path.is_relative_to(target_dir)
        or not path.is_file() or not os.access(path, os.X_OK)
    ):
        raise ValueError("built executable escaped private target custody or is unavailable")
    return path


def selected_executable(output, target_dir, name, kind):
    candidates = []
    for line in output.splitlines():
        event = json.loads(line)
        target = event.get("target", {})
        if (
            event.get("reason") == "compiler-artifact" and target.get("name") == name
            and target.get("kind") == [kind] and event.get("executable")
            and event.get("profile", {}).get("test") is (kind == "lib")
        ):
            candidates.append(Path(event["executable"]))
    if len(candidates) != 1:
        raise ValueError(f"expected exactly one built {name} {kind} executable")
    return private_executable(candidates[0], target_dir)


def build_cli(work, evidence, env):
    output = command(evidence, "build-cli", [
        "cargo", f"+{TOOLCHAIN}", "build", "--locked", "--offline", "--jobs", "2",
        "--target", TARGET, "-p", "exacopy-cli", "--bin", "exacopy", "--message-format=json",
    ], env=env, timeout=GATE_SECONDS)
    return selected_executable(output, work / "target" / TARGET, "exacopy", "bin")


def build_native_suite(work, evidence, env, family):
    owner = UNIT_OWNERS[family]
    output = command(evidence, f"build-{family}", [
        "cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
        "--target", TARGET, "-p", owner, "--lib", "--no-run", "--message-format=json",
    ], env=env, timeout=GATE_SECONDS)
    return selected_executable(output, work / "target" / TARGET, owner.replace("-", "_"), "lib")


def verify_listing(output, expected):
    cases = [line for line in output.splitlines() if line.startswith(PREFIX)]
    if sorted(cases) != sorted(f"{name}: test" for name in expected):
        raise ValueError("native fixture test inventory differs from the exact manifest")


def oracle_inputs():
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    pins = [entry for entry in lock["package"] if entry["name"] == "blake3"
            and entry.get("source", "").startswith("registry+")]
    if len(pins) != 1:
        raise ValueError("expected exactly one registry BLAKE3 package pin")
    pin = pins[0]
    package = f"blake3-{pin['version']}"
    cache = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry"
    archives = list(cache.glob(f"cache/*/{package}.crate"))
    sources = list(cache.glob(f"src/*/{package}/c"))
    if len(archives) != 1 or len(sources) != 1 or digest(archives[0]) != pin["checksum"]:
        raise ValueError("pinned portable BLAKE3 archive or extracted source unavailable")
    source = sources[0]
    with tarfile.open(archives[0]) as archive:
        for name in C_INPUTS:
            member = archive.getmember(f"{package}/c/{name}")
            content = archive.extractfile(member) if member.isfile() else None
            if content is None:
                raise ValueError("expected a regular portable BLAKE3 archive member")
            with content:
                if content.read() != (source / name).read_bytes():
                    raise ValueError(f"portable BLAKE3 input {name} differs from the locked archive")
    return source, pin["checksum"]


def build_oracle(work, evidence, env):
    directory = work / "oracle"
    directory.mkdir(mode=0o700)
    for name in ("build-hash.sh", "hash.c"):
        shutil.copyfile(HASH_SOURCE / name, directory / name)
    source, archive_digest = oracle_inputs()
    command(evidence, "cc", ["cc", "--version"], env=env)
    command(evidence, "build-oracle", ["bash", directory / "build-hash.sh", source], env=env)
    return private_executable(directory / "hash", directory), archive_digest

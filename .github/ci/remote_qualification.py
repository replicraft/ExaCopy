#!/usr/bin/env python3
"""Collect unsigned native facts or run a separately qualified remote CLI campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
from contextlib import contextmanager

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "qualification"))
from linux_remote_source import source_identity
import linux_remote_substrate
from native_supervision import (
    CleanupUnconfirmed, LOG_LIMIT, file_digest, interrupted, logged_command, process_record,
    write_json,
)

DIRECT = "direct-pinned-tcp-v1"
EMBEDDED = "embedded-wireguard-tcp-v1"
ROUTES = (DIRECT, EMBEDDED)
DEPLOYMENT_PATHS = (
    "destination", "owner_profile", "ssh_profile", "qualification", "trust",
    "source_small", "source_interrupt", "sshd_log",
)
FACTS_MARKER = b"EXACOPY_REMOTE_NATIVE_FACTS "
FIXTURES = Path("apps/exacopy-cli/verification/remote")
CONFIG_LIMIT = 16 * 1024
FEATURES = {DIRECT: "experimental-ssh-capture", EMBEDDED: "experimental-ssh-wireguard"}
PIN_INPUTS = (
    "specs/dependencies/apfs-source.toml", "specs/dependencies/transport-source.toml",
)
RUST = "+1.100.0"
RUST_HOSTS = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu"}
MAX_BINARY = 512 * 1024 * 1024


@contextmanager
def fresh_target(target: Path):
    target.mkdir(mode=0o700)
    try:
        yield
    except CleanupUnconfirmed:
        # An unconfirmed process may still hold this task-owned directory.
        raise
    except BaseException:
        shutil.rmtree(target)
        raise
    else:
        shutil.rmtree(target)


def closed_object(items: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("repeated deployment field")
        result[key] = value
    return result


def absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("expected an absolute native path")
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("expected an existing canonical native path")
    return path


def file_observation(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev, details.st_ino, details.st_mode, details.st_nlink,
        details.st_uid, details.st_size, details.st_mtime_ns, details.st_ctime_ns,
    )


def load_deployment(route: str, *, campaign: bool) -> dict[str, Path]:
    path = absolute_path(os.environ.get("EXACOPY_REMOTE_DEPLOYMENT"))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 0 < metadata.st_size <= CONFIG_LIMIT
        ):
            raise ValueError("deployment must be a bounded owner-only 0600 regular file")
        raw = source.read(CONFIG_LIMIT + 1)
        current = os.fstat(source.fileno())
        if len(raw) != metadata.st_size or file_observation(metadata) != file_observation(current):
            raise ValueError("deployment changed while read")
    value = json.loads(raw, object_pairs_hook=closed_object)
    expected = DEPLOYMENT_PATHS if campaign else ("destination",)
    if (
        not isinstance(value, dict) or set(value) != {"schema", "route", *expected}
        or value["schema"] != "exacopy-ci-remote-deployment-v1" or value["route"] != route
    ):
        raise ValueError("deployment schema, fields or selected route mismatch")
    paths = {field: absolute_path(value[field]) for field in expected}
    root = paths["destination"]
    if not root.is_dir() or next(root.iterdir(), None) is not None:
        raise ValueError("destination must be an empty dedicated directory")
    for field, dependency in paths.items():
        if field == "destination":
            continue
        valid_kind = dependency.is_dir() if field == "owner_profile" else dependency.is_file()
        if not valid_kind or dependency.is_relative_to(root):
            raise ValueError("campaign inputs must use the required native types outside the destination")
    if campaign and (
        len(set(paths.values())) != len(paths) or paths["qualification"].samefile(paths["trust"])
    ):
        raise ValueError("campaign inputs must be distinct, including qualification and trust")
    return paths


def build_environment(target: Path) -> dict[str, str]:
    path = Path.cwd()
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for directory in (cargo_home, *(ancestor / ".cargo" for ancestor in (path, *path.parents))):
        if any(os.path.lexists(directory / name) for name in ("config", "config.toml")):
            raise ValueError("native checks require Cargo without additional configuration")
    env = {key: os.environ[key] for key in (
        "PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "LANG", "LC_ALL",
    ) if key in os.environ}
    env.update(CARGO_TARGET_DIR=os.fspath(target), CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never")
    return env


def binary_observation(path: Path) -> tuple[int, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
            or not 4 <= before.st_size <= MAX_BINARY or source.read(4) != b"\x7fELF"
        ):
            raise ValueError("expected bounded native ELF")
        source.seek(0)
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = source.read(min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("selected ELF ended before its held extent")
            hasher.update(chunk)
            remaining -= len(chunk)
        if (
            source.read(1) or file_observation(before) != file_observation(os.fstat(source.fileno()))
            or file_observation(before) != file_observation(path.lstat())
        ):
            raise ValueError("selected ELF changed while measured")
    return before.st_size, hasher.hexdigest()


def verified_pins(stage: str, evidence: Path, env: dict[str, str]) -> dict[str, str]:
    logs = {}
    for name in ("apfs", "transport"):
        log = evidence / f"pin-{stage}.{name}.log"
        result = logged_command([sys.executable, "-B", f"tools/{name}_source.py"], log, 90, env=env)
        logs[log.name] = file_digest(log)
        if not result.passed():
            raise ValueError(f"{name} pinned source could not be verified at {stage} ({result.status})")
    return logs


def verify_cargo_artifact(log: Path, expected: Path, feature: str) -> list[str]:
    outputs = []
    with log.open(encoding="utf-8", errors="replace") as cargo:
        if log.stat().st_size > LOG_LIMIT:
            raise ValueError("Cargo build evidence exceeds its input bound")
        for line in cargo:
            if not line.startswith("{"):
                continue
            message = json.loads(line)
            if (
                message.get("reason") != "compiler-artifact"
                or message.get("target", {}).get("kind") != ["bin"]
            ):
                continue
            if message.get("executable"):
                outputs.append(message)
    if len(outputs) != 1:
        raise ValueError("Cargo did not report exactly one executable")
    unit = outputs[0]
    if (
        unit["executable"] != os.fspath(expected) or unit["target"]["name"] != "exacopy"
        or set(unit["features"]) != ({FEATURES[DIRECT], feature})
        or unit["fresh"] is not False
    ):
        raise ValueError("Cargo did not report the expected freshly built CLI and route feature")
    return sorted(unit["features"])


def build_cli(route: str, evidence: Path, target: Path, env: dict[str, str]) -> tuple[Path, Path]:
    evidence.mkdir(mode=0o700)
    feature = FEATURES[route]
    command = [
        "cargo", RUST, "build", "--release", "--offline", "--locked", "--no-default-features",
        "-p", "exacopy-cli", "--bin", "exacopy", "--features", feature,
        "--message-format=json-render-diagnostics",
    ]
    manifest = evidence / "result.json"
    report = {
        "schema": "exacopy.linux-remote-cli-build.v1",
        "status": "blocked", "route": route, "features": [feature], "argv": command,
    }
    log = evidence / "build.log"
    toolchain_log = evidence / "rustc.log"
    try:
        report["source_before"] = source_identity(REPO)
        report["pin_inputs_sha256"] = {item: file_digest(Path(item)) for item in PIN_INPUTS}
        logs = verified_pins("pre", evidence, env)
        toolchain = logged_command(["rustc", RUST, "-vV"], toolchain_log, 30, env=env)
        report["toolchain"] = process_record(toolchain, toolchain_log)
        host = RUST_HOSTS.get(os.uname().machine)
        if (
            not toolchain.passed() or host is None
            or not {"release: 1.100.0", f"host: {host}"} <= set(toolchain_log.read_text().splitlines())
        ):
            raise ValueError("expected pinned native Rust 1.100.0")
        result = logged_command(command, log, 1500, env=env)
        report["process"] = process_record(result, log)
        report["build_log_sha256"] = report["process"]["log_sha256"]
        logs.update(verified_pins("post", evidence, env))
        report["pin_logs_sha256"] = logs
        report["source_after"] = source_identity(REPO)
        if report["source_before"] != report["source_after"]:
            raise ValueError("source changed during the native CLI build")
        if not result.passed():
            raise ValueError(f"native CLI build did not succeed ({result.status})")
        binary = target / "release" / "exacopy"
        report["compiled_features"] = verify_cargo_artifact(log, binary, feature)
        size, digest = binary_observation(binary)
        report.update(status="built", build_sha256=digest, build_size=size)
        return binary, manifest
    finally:
        write_json(manifest, report)


def collect_facts(
    destination: Path, binary: Path, evidence: Path, *, env: dict[str, str], manifest: Path | None,
) -> int:
    command = [
        "cargo", RUST, "test", "--offline", "--locked", "-p", "exacopy-cli",
        "--test", "linux_remote_qualification_facts", "native_facts::emit_unsigned_native_facts",
        "--", "--exact", "--ignored", "--nocapture",
    ]
    evidence.mkdir(mode=0o700)
    report = {
        "schema": "exacopy.linux-remote-native-facts.v1", "status": "blocked",
        "qualifies_remote_download": False,
        "repository_attribution": "locked-cli-build" if manifest else "measured-selected-elf",
    }
    log = evidence / "facts.log"
    try:
        before = source_identity(REPO)
        if manifest:
            verified_pins("facts-pre", evidence, env)
        build_before = binary_observation(binary)
        if manifest:
            build = json.loads(manifest.read_bytes())
            report["build_manifest_sha256"] = file_digest(manifest)
            if (
                build["status"] != "built" or build["source_before"] != before
                or build["source_after"] != before
                or (build["build_size"], build["build_sha256"]) != build_before
            ):
                raise ValueError("selected CLI no longer matches the recorded locked build")
        result = logged_command(
            command, log, 900,
            env=dict(env, EXACOPY_FACTS_DESTINATION=os.fspath(destination),
                     EXACOPY_FACTS_BINARY=os.fspath(binary)),
        )
        write_json(evidence / "process.json", process_record(result, log))
        if manifest:
            verified_pins("facts-post", evidence, env)
        after = source_identity(REPO)
        if before != after or binary_observation(binary) != build_before:
            raise ValueError("source or selected ELF changed while collecting facts")
        report.update(before)
        if log.stat().st_size > LOG_LIMIT:
            raise ValueError("native facts evidence exceeds its input bound")
        observations = []
        with log.open("rb") as transcript:
            for line in transcript:
                if line.startswith(FACTS_MARKER) and len(line) <= CONFIG_LIMIT:
                    observations.append(json.loads(line.removeprefix(FACTS_MARKER)))
                    if len(observations) > 1:
                        break
        if result.status != "exited":
            report["reason"] = result.status
        elif len(observations) != 1:
            report["reason"] = "missing-or-ambiguous-fixture-output"
        elif result.passed() and observations[0].get("status") == "observed":
            facts = observations[0]["facts"]
            report.update(
                status="observed", build_blake3_derive_key=facts["build_blake3_derive_key"],
                destination=facts["destination"],
            )
        else:
            report["reason"] = observations[0].get("reason", "fixture-failed")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error) if type(error) is ValueError else type(error).__name__
    finally:
        write_json(evidence / "facts.json", report)
    return 0 if report["status"] == "observed" else 77


def run_campaign(paths: dict[str, Path], route: str, binary: Path, evidence: Path) -> int:
    command = [
        sys.executable, "-B", str(FIXTURES / "campaign.py"),
        "--binary", os.fspath(binary), "--route", route, "--evidence", os.fspath(evidence / "campaign"),
    ]
    for field in DEPLOYMENT_PATHS:
        command.extend(("--" + field.replace("_", "-"), os.fspath(paths[field])))
    log = evidence / "campaign.log"
    try:
        result = logged_command(command, log, 1500)
        write_json(evidence / "campaign-process.json", process_record(result, log))
    finally:
        try:
            (evidence / "campaign" / "cleanup-unconfirmed.json").lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CleanupUnconfirmed("nested ownership result could not be inspected") from error
        else:
            raise CleanupUnconfirmed("nested CLI cleanup remained unconfirmed")
    if not result.passed():
        return 1 if result.exit_status == 1 else 77
    path = evidence / "campaign" / "summary.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError("missing bounded campaign outcome")
    summary = json.loads(path.read_bytes())
    if (
        summary["schema"] != "exacopy.linux-remote-cli-campaign.v1" or summary["route"] != route
        or summary["status"] != "pass" or type(summary["exit_status"]) is not int
        or summary["exit_status"] != 0 or summary["issues_new_qualification"] is not False
    ):
        raise ValueError("campaign outcome did not establish fixture pass")
    return 0


def run_observation(
    mode: str, root: Path, route: str, binary: Path, manifest: Path,
    evidence: Path, env: dict[str, str],
) -> int:
    facts = evidence / "native-facts"
    collected = collect_facts(root, binary, facts, env=env, manifest=manifest)
    if mode == "request" and collected != 0:
        return collected
    substrate_result = linux_remote_substrate.run(root, evidence / "substrate", environment=env)
    if mode == "hosted" or substrate_result != 0:
        return substrate_result or collected
    recheck = evidence / "native-facts-recheck"
    collected = collect_facts(root, binary, recheck, env=env, manifest=manifest)
    if collected != 0:
        return collected
    if (facts / "facts.json").read_bytes() != (recheck / "facts.json").read_bytes():
        raise ValueError("exact destination or build observations changed around the substrate campaign")
    log = evidence / "request.log"
    result = logged_command([
        sys.executable, "-B", str(FIXTURES / "qualification_request.py"),
        "--binary", os.fspath(binary), "--facts", os.fspath(facts / "facts.json"),
        "--substrate", os.fspath(evidence / "substrate"), "--route", route,
        "--evidence", os.fspath(evidence / "unsigned-request"),
        "--build-manifest", os.fspath(manifest),
    ], log, 90)
    write_json(evidence / "request-process.json", process_record(result, log))
    return 1 if result.exit_status == 1 else 77


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("facts", "hosted", "request", "campaign"))
    parser.add_argument("--route", choices=ROUTES)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--binary", type=Path, help="independently selected ELF for the facts-only mode")
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or os.getuid() != os.geteuid() or os.geteuid() == 0:
        print("Native evidence requires an unprivileged Linux runner.", file=sys.stderr)
        return 77
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        evidence = args.evidence.parent.resolve(strict=True) / args.evidence.name
        parent = evidence.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError("evidence and build cache need an owner-managed parent")
        if Path.cwd() != REPO or evidence.is_relative_to(REPO):
            raise ValueError("evidence and build cache must be outside the clean checkout")
        target = evidence.parent / "exacopy-remote-build-target"
        if target.is_relative_to(REPO) or os.path.lexists(target):
            raise ValueError("expected a fresh dedicated native build target")
        env = build_environment(target)
        destination = absolute_path(os.fspath(args.destination)) if args.destination else None
        if args.mode == "facts":
            if destination is None or args.binary is None or args.route is not None:
                raise ValueError("facts-only mode requires a destination and independently selected ELF")
            binary = absolute_path(os.fspath(args.binary))
            with fresh_target(target):
                return collect_facts(destination, binary, evidence, env=env, manifest=None)
        if args.route is None or args.binary is not None:
            raise ValueError("select an exact route for a recorded locked build")
        if args.mode == "hosted":
            if destination is None:
                raise ValueError("hosted probe requires its dedicated destination")
        else:
            if destination is not None:
                raise ValueError("deployed mode requires a protected deployment")
            campaign = args.mode == "campaign"
            if not shutil.which("b3sum") or (campaign and not shutil.which("findmnt")):
                raise ValueError("native fixture requires b3sum and the CLI campaign also requires findmnt")
            paths = load_deployment(args.route, campaign=campaign)
            destination = paths["destination"]
        evidence.mkdir(mode=0o700)
        with fresh_target(target):
            binary, manifest = build_cli(args.route, evidence / "build", target, env)
            if args.mode == "campaign":
                status = run_campaign(paths, args.route, binary, evidence)
                if status == 0:
                    build = json.loads(manifest.read_bytes())
                    verified_pins("campaign-post", evidence, env)
                    if (
                        source_identity(REPO) != build["source_after"]
                        or binary_observation(binary) != (build["build_size"], build["build_sha256"])
                    ):
                        raise ValueError("source or executable changed around the CLI campaign")
                return status
            return run_observation(args.mode, destination, args.route, binary, manifest, evidence, env)
    except CleanupUnconfirmed:
        print("Native evidence blocked: unconfirmed owned subprocess cleanup; build target retained.", file=sys.stderr)
        return 77
    except (KeyboardInterrupt, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if type(error) is ValueError else type(error).__name__
        print(f"Native evidence blocked: {message}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())

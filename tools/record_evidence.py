#!/usr/bin/env python3
"""Run workspace members' declared obligations and retain revision-bound EVS-1 evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile
import time
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KANI_PIN = Path("crates/foundation/exacopy-model/verification/kani/toolchain.lock.json")
GATES = ("rust", "lean", "kani", "tlc")
RUN_TIMEOUT_SECONDS = 900
TOOL_QUERY_TIMEOUT_SECONDS = 30
NEXTEST_VERSION = "0.9.151"
NEXTEST_VERSION_LINE = re.compile(rf"[ \t]*cargo-nextest[ \t]+{re.escape(NEXTEST_VERSION)}(?:[ \t]|\Z)")
# Match the importer grammar exercised by xtask/src/evidence/nextest/fixtures/transcripts.json.
NEXTEST_MAX_LINE_BYTES = 4096
NEXTEST_MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
NEXTEST_SEPARATOR = "────────────"
NEXTEST_RUN = re.compile(
    r" Nextest run ID [0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    r" with nextest profile: default"
)
NEXTEST_START = re.compile(
    r"    Starting 1 test across (?:1 binary|(?:[2-9]|[1-9][0-9]{1,9}) binaries)"
    r"(?: \(([1-9][0-9]{0,9}) tests? skipped\))?"
)
NEXTEST_TIME = r"(?:0|[1-9][0-9]{0,9})\.[0-9]{3}s"
NEXTEST_TEST = r"([A-Za-z0-9_-]+(?:::[A-Za-z0-9_-]+)?) (.+)"
NEXTEST_PASS = re.compile(rf"        PASS \[ *{NEXTEST_TIME}\] \(1/1\) {NEXTEST_TEST}")
NEXTEST_SLOW = re.compile(rf"        SLOW \[> {NEXTEST_TIME}\] \(───\) {NEXTEST_TEST}")
NEXTEST_SUMMARY = re.compile(
    rf"     Summary \[ *{NEXTEST_TIME}\] 1 test run: 1 passed"
    r"( \(1 slow\))?(?:, ([1-9][0-9]{0,9}) skipped)?"
)
NEXTEST_UNEXPECTED_PRELUDE = re.compile(
    r"(?:(?:Nextest|Starting|Summary|PASS|SLOW|FAIL|SKIP|SKIPPED|RETRY|RETRYING|"
    r"TRY|FLAKY|TIMEOUT|ABORT|CANCEL|CANCELED|CANCELLED|IGNORED|LEAK|LEAKED)"
    r":?(?:[ \t]|\Z)|error[:\[]|Evidence command timed out\.|"
    r"Could not start evidence command:|Could not verify evidence inputs after execution:)"
)
NEXTEST_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")
KANI_OMITTED_ARGUMENT = b"not enough arguments, inserting non-deterministic value"
KANI_PROFILE = b"EXACOPY_EVS_KANI_PROFILE_V1 "
TLC_COUNTS = re.compile(r"^\d+ states generated, (\d+) distinct states found, 0 states left on queue\.$", re.M)


def query(*command):
    return subprocess.check_output(
        command, cwd=ROOT, text=True, timeout=TOOL_QUERY_TIMEOUT_SECONDS,
    ).strip()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def revision():
    return query("git", "rev-parse", "HEAD"), bool(
        query("git", "status", "--porcelain", "--untracked-files=normal")
    )


def workspace_obligations(gate_filter):
    metadata = json.loads(query("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"))
    members = set(metadata["workspace_members"])
    for package in sorted(metadata["packages"], key=lambda entry: entry["manifest_path"]):
        if package["id"] not in members:
            continue
        crate_root = Path(package["manifest_path"]).parent
        ledger = crate_root / "verification/obligations.toml"
        if not ledger.is_file():
            continue
        with ledger.open("rb") as manifest:
            obligations = tomllib.load(manifest)["obligation"]
        for obligation in obligations:
            for gate in obligation["gates"]:
                if gate_filter is None or gate == gate_filter:
                    if gate in ("rust", "kani"):
                        validate_gate_features(package, obligation, gate)
                    yield package["name"], crate_root, obligation, gate


def profile_features(gate, link):
    if gate in ("rust", "kani"):
        return link.get("features", [])
    return ["proof-extraction"] if gate == "lean" else []


def validate_gate_features(package, obligation, gate):
    features = profile_features(gate, obligation[gate])
    label = f'{package["name"]} {obligation["id"]}'
    scope = {"rust": "Rust", "kani": "Kani"}[gate]
    if not isinstance(features, list) or any(not isinstance(name, str) for name in features):
        raise ValueError(f"{label}: {scope} gate features must be a list of names")
    if len(features) != len(set(features)):
        raise ValueError(f"{label}: duplicate {scope} gate features")
    for name in features:
        if name not in package["features"]:
            raise ValueError(f"{label}: undeclared {scope} gate feature {name!r}")
    return features


def tool_version(crate_root, gate):
    verification = crate_root / "verification"
    if gate == "rust":
        versions = query("cargo", "nextest", "--version").splitlines()
        return "cargo-nextest", versions[0] if versions else "unavailable"
    if gate == "lean":
        return "Lean", (verification / "lean-toolchain").read_text(encoding="utf-8").strip()
    if gate == "kani":
        crate_pin = verification / "kani/toolchain.lock.json"
        lock = read_json(crate_pin if crate_pin.exists() else ROOT / DEFAULT_KANI_PIN)
        return "Kani", lock["kani"]["version"]
    lock = read_json(verification / "tla/toolchain.lock.json")
    return "TLC", f"TLC {lock['tlc']['version']} (tla2tools {lock['tlc']['release']})"


def kani_runner(crate_root, selection):
    if (not isinstance(selection, str) or not selection.startswith("verification/")
            or "\\" in selection or ":" in selection
            or any(part in ("", ".", "..") for part in selection.split("/"))):
        raise ValueError("Kani runner must be an owner-relative file under verification/")
    path = crate_root
    for part in selection.split("/"):
        path /= part
        if path.is_symlink():
            raise ValueError("Kani runner must not contain a symlink")
    if not path.is_file():
        raise ValueError("Kani runner must be an owned regular file")
    return path


def gate_command(package, crate_root, gate, link):
    features = profile_features(gate, link)
    feature_args = ["--no-default-features", "--features", ",".join(features)] if features else []
    if gate == "rust":
        return (["cargo", "nextest", "run", "--locked", "-p", package] + feature_args
                + ["--no-tests", "fail", "--", "--exact", link["test"]])
    script = (kani_runner(crate_root, link["runner"]) if gate == "kani" and "runner" in link
              else crate_root / "verification/check.sh")
    command = [script.relative_to(ROOT).as_posix(), gate]
    if gate == "kani":
        command += feature_args
    return command


def matches_rust_report(report, package, test):
    if len(report) not in (6, 7):
        return False
    if not NEXTEST_RUN.fullmatch(report[1]) or report[-2] != NEXTEST_SEPARATOR:
        return False
    starting = NEXTEST_START.fullmatch(report[2])
    passed = NEXTEST_PASS.fullmatch(report[-3])
    summary = NEXTEST_SUMMARY.fullmatch(report[-1])
    if not (starting and passed and summary):
        return False
    binary, test_name = passed.groups()
    if binary.partition("::")[0] != package or test_name != test:
        return False
    slow_reported = len(report) == 7
    if slow_reported:
        slow = NEXTEST_SLOW.fullmatch(report[3])
        if not slow or slow.groups() != passed.groups():
            return False
    return slow_reported == bool(summary[1]) and starting[1] == summary[2]


def rust_log_result(log, package, test):
    """Hash the bytes examined from a single open log, including any rejected lines."""
    checksum = hashlib.sha256()
    report = []
    total = 0
    valid = True
    with log.open("rb") as source:
        while valid and (raw_line := source.readline(NEXTEST_MAX_LINE_BYTES + 1)):
            checksum.update(raw_line)
            total += len(raw_line)
            if (len(raw_line) > NEXTEST_MAX_LINE_BYTES or total > NEXTEST_MAX_TRANSCRIPT_BYTES
                    or not raw_line.endswith(b"\n")):
                valid = False
                break
            try:
                line = raw_line[:-1].removesuffix(b"\r").decode("utf-8")
            except UnicodeDecodeError:
                valid = False
                break
            if NEXTEST_CONTROL.search(line):
                valid = False
            elif report or line == NEXTEST_SEPARATOR:
                report.append(line)
                valid = len(report) <= 7
            else:
                diagnostic = line.lstrip(" \t")
                if diagnostic[:1].isspace() or NEXTEST_UNEXPECTED_PRELUDE.match(diagnostic):
                    valid = False
        if not valid:
            # Keep the digest of the entire raw artifact even after refusing its transcript.
            while chunk := source.read(64 * 1024):
                checksum.update(chunk)
    return checksum.hexdigest(), valid and matches_rust_report(report, package, test)


def matches_kani_profile(log, features):
    expected = KANI_PROFILE + ("--no-default-features --features " + ",".join(features)).encode()
    # Allow CRLF and one byte to detect an oversized acknowledgement.
    limit = len(expected) + 3
    found = False
    try:
        with log.open("rb") as data:
            while line := data.readline(limit):
                if line.startswith(KANI_PROFILE):
                    acknowledgement = line[:-1].removesuffix(b"\r") if line.endswith(b"\n") else line
                    if found or acknowledgement != expected:
                        return False
                    found = True
                # Drain this physical line so a chunk boundary cannot start an acknowledgement.
                while len(line) == limit and not line.endswith(b"\n"):
                    line = data.readline(limit)
    except OSError:
        return False
    return found


def kani_log_issue(log, features):
    overlap = b""
    with log.open("rb") as source:
        while chunk := source.read(8192):
            window = overlap + chunk
            if KANI_OMITTED_ARGUMENT in window:
                return "Kani supplied a nondeterministic value for an omitted call argument."
            overlap = window[1 - len(KANI_OMITTED_ARGUMENT):]
    if features and not matches_kani_profile(log, features):
        return "Kani dispatcher did not confirm the exact requested feature profile."
    return None


def run_gate(command, gate, link, log, trace):
    """Include both full TLC reports and distribute the negative trace separately."""
    started = datetime.now(timezone.utc)
    clock = time.monotonic_ns()
    state_count = None
    with tempfile.TemporaryDirectory(prefix="exacopy-tlc-evidence-") as scratch:
        environment = os.environ | {
            "RUSTC_WRAPPER": "",
            "RUSTC_WORKSPACE_WRAPPER": "",
            "CARGO_INCREMENTAL": "0",
            "EXACOPY_VERIFICATION_SCRATCH": scratch,
        }
        if gate == "tlc":
            environment["TLC_LOG_DIR"] = scratch
        with log.open("xb") as output:
            try:
                with subprocess.Popen(
                    command, cwd=ROOT, env=environment, stdout=output,
                    stderr=subprocess.STDOUT, start_new_session=os.name == "posix",
                ) as process:
                    try:
                        result = process.wait(timeout=RUN_TIMEOUT_SECONDS)
                    except subprocess.TimeoutExpired:
                        if os.name == "posix":
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        else:
                            process.kill()
                        process.wait()
                        output.write(b"\nEvidence command timed out.\n")
                        result = 124
            except OSError as error:
                output.write(f"\nCould not start evidence command: {error}\n".encode())
                result = 127
            if gate == "tlc":
                positive = Path(scratch) / (Path(link["config"]).stem + ".log")
                negative = Path(scratch) / (Path(link["negative_control"]).stem + ".log")
                if positive.is_file():
                    report = positive.read_bytes()
                    output.write(b"\n--- TLC safety report ---\n" + report)
                    match = TLC_COUNTS.search(report.decode("utf-8", errors="replace"))
                    state_count = match.group(1) if match else None
                if negative.is_file():
                    report = negative.read_bytes()
                    output.write(b"\n--- TLC negative control ---\n" + report)
                    with trace.open("xb") as trace_file:
                        trace_file.write(report)
                if result == 0 and (not state_count or not trace.is_file()):
                    output.write(b"\nTLC safety counts or negative trace missing.\n")
                    result = 1
    return started, (time.monotonic_ns() - clock) // 1_000_000, result, state_count


def record_gate(output_dir, package, crate_root, obligation, gate, source_revision, target):
    link = obligation[gate]
    command = gate_command(package, crate_root, gate, link)
    source = crate_root / obligation["source"]
    generated = crate_root / link["generated"] if gate == "lean" else None
    input_digest = digest(source)
    lockfile_digest = digest(ROOT / "Cargo.lock")
    extraction_digest = digest(generated) if generated else None
    evidence_id = str(uuid.uuid4())
    log = output_dir / f"{evidence_id}.log"
    trace = output_dir / f"{evidence_id}.trace"
    try:
        tool, version = tool_version(crate_root, gate)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"{obligation['id']} {gate} version could not be read: {error}", flush=True)
        tool, version = gate, "unavailable"
    started, duration, status, state_count = run_gate(command, gate, link, log, trace)
    try:
        current_commit, dirty = revision()
        same_inputs = (
            current_commit == source_revision and digest(source) == input_digest
            and digest(ROOT / "Cargo.lock") == lockfile_digest
            and (generated is None or digest(generated) == extraction_digest)
        )
    except (OSError, subprocess.SubprocessError) as error:
        with log.open("ab") as output:
            output.write(f"\nCould not verify evidence inputs after execution: {error}\n".encode())
        dirty, same_inputs = True, False
    outcome = "fail" if status else "pass"
    justification = "Recorded from tool execution. Independent review is pending."
    if status == 0:
        if dirty or not same_inputs or version == "unavailable":
            outcome = "blocked"
        if gate == "kani":
            try:
                issue = kani_log_issue(log, profile_features(gate, link))
            except OSError:
                outcome = "blocked"
                justification = "Kani command exited zero. Its log could not be read for acceptance."
            else:
                if issue:
                    outcome = "fail"
                    justification = f"Kani command exited zero. {issue}"
    if gate == "rust":
        try:
            if status != 0:
                artifact_digest = digest(log)
                justification = f"Rust command exited with status {status}. See its retained log."
            else:
                artifact_digest, test_passed = rust_log_result(log, package, link["test"])
                if tool != "cargo-nextest" or not NEXTEST_VERSION_LINE.match(version):
                    outcome = "blocked"
                    justification = f"Rust command exited zero. Evidence requires cargo-nextest {NEXTEST_VERSION}."
                elif not test_passed and outcome == "pass":
                    outcome = "fail"
                    justification = (
                        "Rust command exited zero. Its log did not confirm one pass of the exact selected test."
                    )
        except OSError as error:
            outcome = "blocked"
            justification = f"Rust command exited with status {status}. Its retained log could not be read."
            print(f"{obligation['id']} {gate} log could not be read: {error}", flush=True)
            artifact_digest = None
    detail = {
        "theorem": link.get("theorem"),
        "extraction_digest": extraction_digest,
        "axioms_tcb": link.get("axioms_tcb", []),
        "state_count": state_count,
        "fairness": link.get("fairness", []),
        "trace_digest": digest(trace) if trace.is_file() else None,
        "harness": link.get("harness"),
        "unwind_bound": str(link["unwind_bound"]) if gate == "kani" else None,
        "fuzz_target": None,
        "corpus_digest": None,
        "budget": None,
        "coverage_denominator": None,
        "mutation_denominator": None,
        "qualification_conditions": [],
    }
    if gate != "rust":
        artifact_digest = digest(log)
    record = {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "requirement_ids": obligation.get("requirement_ids", []),
        "obligation_ids": [obligation["id"]],
        "kind": "test" if gate == "rust" else gate,
        "repository": "replicraft/ExaCopy",
        "commit": source_revision,
        "dirty": dirty or not same_inputs,
        "source_digest": input_digest,
        "generated_input_digest": extraction_digest,
        "lockfile_digest": lockfile_digest,
        "tool": tool,
        "tool_version": version,
        "redacted_command": command,
        "profile": {
            "features": profile_features(gate, link),
            "target": target,
            "os": f"{platform.system()} {platform.release()}",
            "filesystem": None,
            "hardware": platform.machine() or None,
        },
        "started_at": started.isoformat(),
        "duration_ms": str(duration),
        "seeds": link.get("seeds", []),
        "model_bounds": link.get("model_bounds", []),
        "assumptions": obligation["assumptions"],
        "oracle": link["oracle"],
        "outcome": outcome,
        "exit_status": status,
        "artifact_digest": artifact_digest,
        "detail": detail,
        "review": {
            "reviewer": None,
            "independent": False,
            "justification": justification,
        },
        "synthetic": False,
    }
    with (output_dir / f"{evidence_id}.json").open("x", encoding="utf-8") as evidence:
        json.dump(record, evidence, indent=2)
        evidence.write("\n")
    print(f"{obligation['id']} {gate}: {outcome} ({log.name})", flush=True)
    return outcome == "pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--gate", choices=GATES)
    args = parser.parse_args()
    output = args.output_directory.resolve()
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / "target"):
        parser.error("Output must be outside the worktree or under its ignored target directory")
    commit, dirty = revision()
    if dirty:
        parser.error("Evidence requires a clean checkout of a committed revision")
    target = next(
        line.removeprefix("host: ") for line in query("rustc", "-vV").splitlines()
        if line.startswith("host: ")
    )
    try:
        work = list(workspace_obligations(args.gate))
    except ValueError as error:
        parser.error(str(error))
    if not work:
        parser.error("The requested selection has no obligations")
    output.mkdir(parents=True, exist_ok=True)
    results = [record_gate(output, *scope, commit, target) for scope in work]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

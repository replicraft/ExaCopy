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
                    yield package["name"], crate_root, obligation, gate


def tool_version(crate_root, gate):
    verification = crate_root / "verification"
    if gate == "rust":
        return "cargo-nextest", query("cargo", "nextest", "--version").splitlines()[0]
    if gate == "lean":
        return "Lean", (verification / "lean-toolchain").read_text(encoding="utf-8").strip()
    if gate == "kani":
        crate_pin = verification / "kani/toolchain.lock.json"
        lock = read_json(crate_pin if crate_pin.exists() else ROOT / DEFAULT_KANI_PIN)
        return "Kani", lock["kani"]["version"]
    lock = read_json(verification / "tla/toolchain.lock.json")
    return "TLC", f"TLC {lock['tlc']['version']} (tla2tools {lock['tlc']['release']})"


def gate_command(package, crate_root, gate, link):
    if gate == "rust":
        return [
            "cargo", "nextest", "run", "--locked", "-p", package,
            "--no-tests", "fail", "--", "--exact", link["test"],
        ]
    script = crate_root / "verification/check.sh"
    return [script.relative_to(ROOT).as_posix(), gate]


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
    if status == 0 and (dirty or not same_inputs or version == "unavailable"):
        outcome = "blocked"
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
            "features": ["proof-extraction"] if gate == "lean" else [],
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
        "artifact_digest": digest(log),
        "detail": detail,
        "review": {
            "reviewer": None,
            "independent": False,
            "justification": "Recorded from tool execution. Independent review is pending.",
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
    work = list(workspace_obligations(args.gate))
    if not work:
        parser.error("The requested selection has no obligations")
    output.mkdir(parents=True, exist_ok=True)
    results = [record_gate(output, *scope, commit, target) for scope in work]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

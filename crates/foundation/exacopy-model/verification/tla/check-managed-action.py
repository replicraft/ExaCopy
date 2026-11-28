#!/usr/bin/env python3
"""Run the bounded ManagedAction model and its exact controls."""

from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent.parent
MODEL = "ManagedAction"
TIMEOUT = 120
MAX_REPORT_BYTES = 4 * 1024 * 1024
HEALTHY_ACTIONS = (
    "Claim", "SubmitIntent", "PersistIntent", "ConfirmIntent", "CreateChildJob",
    "ObserveCreatedJob", "FailChildCreation", "SubmitChildRename",
    "SettleVerified", "SettleConflict", "SettleUnknown", "SettleIncomplete",
    "SubmitObservation", "PersistObservation", "InterruptObservation", "ReadbackObservation",
    "ConfirmObservation", "InterruptIntent", "Withdraw", "Crash", "Reopen",
    "RefuseSpentActivation", "RefuseCompetingActivation",
)
CHILD_PREFIX = ("Claim", "SubmitIntent", "PersistIntent", "ConfirmIntent", "CreateChildJob")
VERIFIED_CHILD = CHILD_PREFIX + ("ObserveCreatedJob", "SubmitChildRename", "SettleVerified")
MUTANTS = (
    ("ManagedActionEarlyCreate", "CreateRequiresConfirmedIntent",
     ("Claim", "SubmitIntent", "PersistIntent", "CreateChildJob"), ("ConfirmIntent",)),
    ("ManagedActionDuplicateCreate", "AtMostOneChildCreation",
     CHILD_PREFIX + ("CreateChildJob",), ()),
    ("ManagedActionTrustPristine", "AtMostOneActivation",
     ("Claim", "SubmitIntent", "InterruptIntent", "Crash", "Reopen", "Claim"), ("PersistIntent",)),
    ("ManagedActionForeignReceipt", "AssociationRequiresBoundReceipt",
     VERIFIED_CHILD + ("SubmitObservation",), ()),
    ("ManagedActionEarlyAssociation", "AssociationRequiresConfirmedEvidence",
     VERIFIED_CHILD + ("SubmitObservation", "ConfirmObservation"),
     ("PersistObservation", "ReadbackObservation")),
)
CASES = (MODEL, *(config for config, _, _, _ in MUTANTS))
COUNTS = re.compile(
    r"^([0-9]+) states generated, ([0-9]+) distinct states found, "
    r"([0-9]+) states left on queue\.$", re.MULTILINE,
)
DEPTH = re.compile(r"^The depth of the complete state graph search is ([0-9]+)\.$", re.MULTILINE)
COVERAGE = re.compile(r"^<([A-Za-z][A-Za-z0-9_]*) line [^>\n]*>: ([0-9]+):([0-9]+)$", re.MULTILINE)
VIOLATION = re.compile(r"^Error: Invariant ([A-Za-z][A-Za-z0-9_]*) is violated\.$", re.MULTILINE)
STATE = re.compile(r"^State ([0-9]+): <([^>\n]+)>$", re.MULTILINE)
ACTION = re.compile(r"^([A-Za-z][A-Za-z0-9_]*) line .+$")


class GateFailure(Exception):
    """The transcript does not establish the expected model result."""


def require(condition, message):
    if not condition:
        raise GateFailure(message)


def check_healthy(status, transcript):
    require(status == 0, f"{MODEL} exited {status}")
    lines = transcript.splitlines()
    require(
        lines.count("Model checking completed. No error has been found.") == 1
        and not any(line.startswith("Error:") for line in lines),
        f"{MODEL} did not complete successfully",
    )
    summaries = COUNTS.findall(transcript)
    require(len(summaries) == 1, f"{MODEL} requires one state summary")
    generated, distinct, queued = map(int, summaries[0])
    require(generated >= distinct > 1 and queued == 0, f"{MODEL} did not exhaust its state graph")
    depths = DEPTH.findall(transcript)
    require(len(depths) == 1 and int(depths[0]) > 1, f"{MODEL} requires one complete graph depth")
    actions = {}
    entries = COVERAGE.findall(transcript)
    for name in HEALTHY_ACTIONS:
        counts = [(int(unique), int(total)) for action, unique, total in entries if action == name]
        require(len(counts) == 1, f"{MODEL} requires one coverage row for {name}")
        unique, total = counts[0]
        require(total > 0 and unique <= total, f"{MODEL} did not explore {name}")
        actions[name] = {"distinct": unique, "total": total}
    return {"generated": generated, "distinct": distinct, "queued": queued,
            "depth": int(depths[0]), "actions": actions}


def check_mutant(status, transcript, invariant, causal, forbidden):
    require(status == 12, f"expected an invariant violation, got TLC exit {status}")
    errors = [line for line in transcript.splitlines() if line.startswith("Error:")]
    require(
        VIOLATION.findall(transcript) == [invariant] and errors == [
            f"Error: Invariant {invariant} is violated.",
            "Error: The behavior up to this point is:",
        ],
        f"expected the exact {invariant} violation and its counterexample",
    )
    states = STATE.findall(transcript)
    require(
        len(states) >= 2
        and len(states) == sum(line.startswith("State ") for line in transcript.splitlines())
        and [int(number) for number, _ in states] == list(range(1, len(states) + 1))
        and states[0][1] == "Initial predicate",
        "counterexample lacks a complete contiguous trace",
    )
    labels = [ACTION.fullmatch(label) for _, label in states[1:]]
    require(all(labels), "counterexample includes an unknown transition label")
    actions = [label[1] for label in labels]
    subsequent = iter(actions)
    require(
        actions[-1] == causal[-1] and all(action in subsequent for action in causal)
        and not set(actions).intersection(forbidden),
        f"counterexample has the wrong causal trace. Required {causal!r}, forbidden {forbidden!r}",
    )
    return {"invariant": invariant, "actions": actions}


def source_inputs():
    return (
        CRATE / "verification/check.sh",
        HERE / "check-managed-action.sh",
        HERE / "check-managed-action.py",
        HERE / "managed_action_runner_test.py",
        HERE / "toolchain.lock.json",
        HERE / f"{MODEL}.tla",
        *(HERE / f"{case}.cfg" for case in CASES),
    )


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def input_hashes(inputs):
    return {path.relative_to(CRATE).as_posix(): digest(data) for path, data in inputs.items()}


def emit_receipt(logs, suffix, fields):
    path = logs / f"{MODEL}.{suffix}.json"
    data = json.dumps(fields, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8") as handle:
        handle.write(data)
    print(f"--- {path.name} ---\n{data}", end="", flush=True)


def execute(command, work, report):
    env = {**os.environ, "LC_ALL": "C"}
    for key in ("JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"):
        env.pop(key, None)
    with report.open("xb") as output:
        try:
            return subprocess.run(
                command, cwd=work, env=env,
                stdout=output, stderr=subprocess.STDOUT, timeout=TIMEOUT,
                check=False,
            ).returncode
        except subprocess.TimeoutExpired:
            print(f"{report.name} expired after {TIMEOUT} seconds", flush=True)
            return 124
        except OSError as error:
            print(f"{report.name} could not launch: {error}", flush=True)
            return 127


def read_report(report):
    with report.open("rb") as stream:
        prefix = stream.read(MAX_REPORT_BYTES + 1)
    complete = len(prefix) <= MAX_REPORT_BYTES
    print(f"--- BEGIN RAW {report.name} ---", flush=True)
    sys.stdout.buffer.write(prefix[:MAX_REPORT_BYTES])
    if not prefix[:MAX_REPORT_BYTES].endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()
    print(f"--- END RAW {report.name} ---", flush=True)
    if not complete:
        print(f"{report.name}: stdout preview truncated at {MAX_REPORT_BYTES} bytes", flush=True)
    return prefix, {
        "log": report.name, "log_sha256": file_digest(report),
        "log_bytes": report.stat().st_size, "stdout_complete": complete,
    }


def run_report(command, work, path, reports):
    try:
        status = execute(command, work, path)
    except GateFailure as error:
        _, evidence = read_report(path)
        reports[path.stem] = {**evidence, "interrupted": str(error)}
        raise
    raw, evidence = read_report(path)
    evidence["exit"] = status
    reports[path.stem] = evidence
    require(evidence["stdout_complete"], f"{path.name} exceeded the raw evidence limit")
    return status, raw.decode("utf-8", errors="strict")


def check_jdk(java, work, logs, pin, reports):
    status, version = run_report(
        [java, "-XshowSettings:properties", "-version"],
        work, logs / f"{MODEL}.jdk.log", reports,
    )
    properties = {line.strip() for line in version.splitlines()}
    require(
        status == 0 and {
            f"java.runtime.version = {pin['runtime_version']}",
            f"java.vendor = {pin['vendor']}",
        } <= properties,
        "Java runtime does not match the locked Temurin runtime and vendor",
    )


def run_model(java, jar, work, scratch, logs, reports, case, validate):
    status, transcript = run_report(
        [
            java, "-XX:+UseParallelGC", "-Xmx256m",
            "-Djava.rmi.server.hostname=127.0.0.1", "-jar", str(jar),
            "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
            "-metadir", str(scratch / f"{case}.states"),
            "-config", f"{case}.cfg", f"{MODEL}.tla",
        ],
        work, logs / f"{case}.log", reports,
    )
    reports[case]["checked"] = validate(status, transcript)


def input_snapshot(jar):
    return {
        "sources": {path.relative_to(CRATE).as_posix(): file_digest(path) for path in source_inputs()},
        "tlc_jar_sha256": file_digest(jar),
    }


def gate(scratch, logs, original_jar):
    inputs = {path: path.read_bytes() for path in source_inputs()}
    pinned = json.loads(inputs[HERE / "toolchain.lock.json"])
    before = {
        "sources": input_hashes(inputs),
        "tlc_jar_sha256": file_digest(original_jar),
    }
    reports = {}
    result = {"reports": reports, "passed": False}
    emit_receipt(logs, "inputs", before)
    try:
        java = shutil.which("java")
        require(java is not None, "the locked Temurin runtime is required")
        java = str(Path(java).resolve(strict=True))
        require(before["tlc_jar_sha256"] == pinned["tlc"]["sha256"], "TLC JAR digest mismatch")
        jar = scratch / "tla2tools.jar"
        shutil.copyfile(original_jar, jar)
        require(file_digest(jar) == pinned["tlc"]["sha256"], "staged TLC JAR digest mismatch")
        work = scratch / "model"
        work.mkdir()
        for name in (f"{MODEL}.tla", *(f"{case}.cfg" for case in CASES)):
            (work / name).write_bytes(inputs[HERE / name])
        check_jdk(java, work, logs, pinned["jdk"], reports)
        run_model(java, jar, work, scratch, logs, reports, MODEL, check_healthy)
        for case, invariant, causal, forbidden in MUTANTS:
            validate = partial(check_mutant, invariant=invariant, causal=causal, forbidden=forbidden)
            run_model(java, jar, work, scratch, logs, reports, case, validate)
    except (GateFailure, OSError, ValueError) as error:
        result["failure"] = str(error)
    try:
        result["inputs_after"] = input_snapshot(original_jar)
        if result["inputs_after"] != before:
            result["input_failure"] = "ManagedAction source or tool inputs changed during the run"
    except OSError as error:
        result["input_failure"] = f"ManagedAction input recheck failed: {error}"
    result["passed"] = not any(field in result for field in ("failure", "input_failure"))
    emit_receipt(logs, "results", result)
    return 0 if result["passed"] else 1


def interrupted(signum, _frame):
    raise GateFailure(f"ManagedAction interrupted by signal {signal.Signals(signum).name}")


def main():
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        jar_path = os.environ.get("TLA2TOOLS_JAR")
        require(jar_path, "TLA2TOOLS_JAR must select the locked TLC JAR")
        original_jar = Path(jar_path).resolve(strict=True)
        with tempfile.TemporaryDirectory(
            prefix="exacopy-managed-action.", dir=os.environ.get("EXACOPY_VERIFICATION_SCRATCH"),
        ) as temp:
            scratch = Path(temp).resolve()
            logs = Path(os.environ.get("TLC_LOG_DIR", scratch / "logs")).resolve()
            require(logs != HERE and HERE not in logs.parents, "TLC_LOG_DIR must be outside model sources")
            logs.mkdir(parents=True, exist_ok=True)
            return gate(scratch, logs, original_jar)
    except (GateFailure, OSError, ValueError) as error:
        print(f"{MODEL}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

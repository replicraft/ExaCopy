#!/usr/bin/env python3
"""Run the finite compiler-job retirement model and retain each TLC report."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
MODEL = "PublicationBuildRetirement"
MUTANTS = {
    "strict-stop": ("OwnedRetirementOnly", "RequestRetirement"),
    "foreign-job": ("OwnedRetirementOnly", "RequestRetirement"),
    "ignore-root": ("OwnedRetirementOnly", "RequestRetirement"),
    "late-request": ("OwnedRetirementOnly", "RequestRetirement"),
    "ignore-stop": ("QuiescenceIsObserved", "ClassifyQuiesced"),
    "ignore-stdout": ("QuiescenceIsObserved", "ClassifyQuiesced"),
    "clear-timeout": ("TimeoutIsMonotone", "ClassifyQuiesced"),
    "trust-root-output": ("PreparedImageIsAdmitted", "IssuePreparedImage"),
    "skip-image": ("PreparedImageIsAdmitted", "IssuePreparedImage"),
    "stale-launch": ("FirstSelectorRequiresFreshAuthority", "IssueFirstSelector"),
}
COUNTS = re.compile(r"^\d+ states generated, ([1-9]\d*) distinct states found, 0 states left on queue\.$", re.M)
SELECTOR_REACHED = re.compile(r"^<IssueFirstSelector line .*?>: \d+:[1-9]\d*$", re.M)
TRACE_ACTION = re.compile(r"^State \d+: <([A-Za-z][A-Za-z0-9]*) line ", re.M)
CASE_TIMEOUT = 45


def checked_jar():
    pin = json.loads((BASE / "toolchain.lock.json").read_text(encoding="utf-8"))
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve(strict=True)
    with jar.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != pin["tlc"]["sha256"]:
            raise SystemExit("TLC jar differs from owner pin")
    java = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    properties = {line.strip() for line in java.stderr.splitlines()}
    jdk = pin["jdk"]
    if not {f"java.runtime.version = {jdk['runtime_version']}",
            f"java.vendor = {jdk['vendor']}"} <= properties:
        raise SystemExit(f"Expected pinned Temurin OpenJDK {jdk['version']}")
    return jar


def run_case(jar, scratch, logs, case):
    stem = MODEL if case == "prepare" else f"{MODEL}-{case}"
    command = [
        "java", "-XX:+UseParallelGC", "-Xmx256m", "-Djava.rmi.server.hostname=127.0.0.1",
        "-jar", str(jar), "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
        "-metadir", str(scratch / case), "-config", f"{stem}.cfg", f"{MODEL}.tla",
    ]
    log_path = logs / f"{stem}.log"
    with log_path.open("xb") as log:
        try:
            status = subprocess.run(
                command, cwd=BASE, stdout=log, stderr=subprocess.STDOUT, timeout=CASE_TIMEOUT,
            ).returncode
        except subprocess.TimeoutExpired:
            status = 124
    report = log_path.read_text(encoding="utf-8", errors="replace")
    # The workspace recorder separately indexes one positive report and one negative trace.
    # Forward all cases to its main artifact so the other reports survive its scratch cleanup.
    print(f"--- {stem} (TLC exit {status}) ---", flush=True)
    print(report, end="" if report.endswith("\n") else "\n", flush=True)
    return status, report


def expected_result(case, status, report):
    lines = report.splitlines()
    if case in MUTANTS:
        invariant, action = MUTANTS[case]
        return (status == 12 and f"Error: Invariant {invariant} is violated." in lines
                and TRACE_ACTION.findall(report)[-1:] == [action])
    return (status == 0 and "Model checking completed. No error has been found." in lines
            and COUNTS.search(report) is not None
            and (case == "strict" or SELECTOR_REACHED.search(report) is not None))


def main():
    jar = checked_jar()
    failures = []
    with tempfile.TemporaryDirectory(prefix="exacopy-publication-build-retirement-") as temporary:
        scratch = Path(temporary)
        logs = Path(os.environ.get("TLC_LOG_DIR", temporary)).resolve()
        logs.mkdir(parents=True, exist_ok=True)
        for case in ("prepare", "strict", *MUTANTS):
            status, report = run_case(jar, scratch, logs, case)
            if not expected_result(case, status, report):
                failures.append(case)
    if failures:
        raise SystemExit("Unexpected TLC results for " + ", ".join(failures))


if __name__ == "__main__":
    main()

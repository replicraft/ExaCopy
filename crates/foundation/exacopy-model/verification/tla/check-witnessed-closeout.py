#!/usr/bin/env python3
"""Check the bounded witnessed closeout model and its exact diagnostic traces."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


BASE = Path(__file__).resolve().parent
MODEL = "WitnessedCloseoutPhase"
CASES = {
    "none": None,
    "run-limit": ("BoundedAndExact", "RepeatContinuation"),
    "stale-repeat": ("BoundedAndExact", "RepeatContinuation"),
    "stale-epoch": ("BoundedAndExact", "RepeatContinuation"),
    "reuse-stage": ("BoundedAndExact", "Prepare"),
    "drop-retained": ("BoundedAndExact", "Prepare"),
    "retire-after-intent": ("BoundedAndExact", "Retire"),
    "skip-byte": ("ReservedCapacity", "FirstContinuation"),
    "skip-slot": ("ReservedCapacity", "FirstContinuation"),
    "skip-receipt": ("ReservedCapacity", "FirstContinuation"),
    "move-coverage": ("CoverageFence", "VerifyMetadata"),
    "digest-only": ("CustodyFence", "RecordReady"),
    "revive-permit": ("CurrentReceiptPermit", "CrashReopen"),
    "reuse-unknown": ("CustodyFence", "Promote"),
    "commit-before-barriers": ("CustodyFence", "RecordCommit"),
    "stronger-no-repeat": ("NoResubmitAfterUnknown", "Promote"),
    "reach-repeat-after-two": ("ReachedRepeatAfterTwo", "RepeatContinuation"),
    "reach-late-retire": ("ReachedLateRetire", "Retire"),
    "reach-limit-closeout": ("ReachedPassLimitCloseout", "RecordCommit"),
}
REACHABLE = (
    "FirstContinuation", "RepeatContinuation", "FreshContinuation", "Checkpoint",
    "Witness", "SealWitness", "Retire", "Prepare", "AuthorizeReceipt", "Promote",
    "ConfirmFinal", "RecordCommit", "CrashReopen",
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_toolchain(jar):
    pinned = json.loads((BASE / "toolchain.lock.json").read_text(encoding="utf-8"))
    require(sha256(jar) == pinned["tlc"]["sha256"], "TLC jar differs from the owner pin")
    java = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"], capture_output=True,
        text=True, timeout=30, check=True,
    )
    properties = {line.strip() for line in java.stderr.splitlines()}
    require(
        {f"java.runtime.version = {pinned['jdk']['runtime_version']}",
         f"java.vendor = {pinned['jdk']['vendor']}"} <= properties,
        "Java differs from the owner pin",
    )


def check_positive(status, output):
    counts = re.search(
        r"^([0-9]+) states generated, ([0-9]+) distinct states found, 0 states left on queue\.$",
        output, re.M,
    )
    require(
        status == 0 and "Model checking completed. No error has been found." in output
        and counts is not None and int(counts[2]) > 0,
        f"Healthy {MODEL} did not exhaust its graph (exit {status}).\n{output}",
    )
    for action in REACHABLE:
        require(
            re.search(rf"^<{action} line .*?>: [0-9]+:[1-9][0-9]*$", output, re.M),
            f"Healthy {MODEL} did not cover {action}.",
        )
    print(f"{MODEL} healthy exhausted: {counts[0]}")


def check_control(case, expected, status, output):
    invariant, decisive_action = expected
    actions = re.findall(r"^State [0-9]+: <([A-Za-z][A-Za-z0-9]*) line ", output, re.M)
    require(
        status == 12 and f"Error: Invariant {invariant} is violated." in output.splitlines()
        and actions and actions[-1] == decisive_action,
        f"{case}: expected violation of {invariant} at {decisive_action} (exit {status}).\n{output}",
    )
    if case == "stronger-no-repeat":
        require(
            actions[-5:] == ["Promote", "CrashReopen", "ObserveReceipt", "AuthorizeReceipt", "Promote"],
            "Global no-resubmission did not fail through fresh exact receipt reconciliation.",
        )
    if case == "commit-before-barriers":
        require(
            actions[-2:] == ["Promote", "RecordCommit"],
            "Direct commit did not bypass independent exact-final confirmation.",
        )
    print(f"{MODEL} {case}: {invariant} counterexample at {decisive_action} (exit 12)")


def main():
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve(strict=True)
    verify_toolchain(jar)
    with tempfile.TemporaryDirectory(prefix="exacopy-witnessed-closeout-tlc.") as temporary:
        scratch = Path(temporary)
        logs = Path(os.environ.get("TLC_LOG_DIR", temporary)).resolve()
        require(logs != BASE, "Put TLC logs outside the model source directory")
        logs.mkdir(parents=True, exist_ok=True)
        files = [Path(__file__), BASE / "toolchain.lock.json", BASE / f"{MODEL}.tla"]
        files.extend(BASE / f"{MODEL}-{case}.cfg" for case in CASES)
        bindings = json.dumps(
            {"tla2tools_jar_sha256": sha256(jar), "input_sha256": {
                source.name: sha256(source) for source in files
            }}, sort_keys=True,
        )
        (logs / f"{MODEL}.inputs.json").write_text(bindings + "\n", encoding="utf-8")
        print(bindings)
        for case, expected in CASES.items():
            stem = f"{MODEL}-{case}"
            command = [
                "java", "-XX:+UseParallelGC", "-Xmx256m", "-Djava.rmi.server.hostname=127.0.0.1",
                "-jar", str(jar), "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
                "-metadir", str(scratch / stem), "-config", f"{stem}.cfg", f"{MODEL}.tla",
            ]
            path = logs / f"{stem}.log"
            with path.open("w", encoding="utf-8") as log:
                result = subprocess.run(
                    command, cwd=BASE, stdout=log, stderr=subprocess.STDOUT, timeout=120,
                )
            output = path.read_text(encoding="utf-8")
            if expected is None:
                check_positive(result.returncode, output)
            else:
                check_control(case, expected, result.returncode, output)


if __name__ == "__main__":
    main()

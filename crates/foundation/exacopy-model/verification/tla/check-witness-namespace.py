#!/usr/bin/env python3
"""Check a bounded protected-witness lifetime model and independent negative controls."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
CASES = {
    "healthy": None,
    "reuse-witnessed": ("WitnessPreservesOrigin", "ExternalCreate"),
    "witness-alone": ("RecoveryRequiresPresentTarget", "RecoverPublished"),
    "stale-target": ("RecoveryRequiresPresentTarget", "RecoverPublished"),
    "revive-rename": ("AtMostOneLiveSubmission", "SubmitRename"),
}


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    pin = json.loads((BASE / "toolchain.lock.json").read_text())
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve(strict=True)
    with jar.open("rb") as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == pin["tlc"]["sha256"],
                "TLC jar differs from owner pin")
    java = subprocess.run(["java", "-XshowSettings:properties", "-version"],
                          capture_output=True, text=True, timeout=30, check=True)
    properties = {line.strip() for line in java.stderr.splitlines()}
    require({f"java.runtime.version = {pin['jdk']['runtime_version']}",
             f"java.vendor = {pin['jdk']['vendor']}"} <= properties, "wrong pinned Java runtime")

    with tempfile.TemporaryDirectory(prefix="exacopy-witness-namespace-") as temporary:
        scratch = Path(temporary)
        logs = Path(os.environ.get("TLC_LOG_DIR", temporary)).resolve()
        logs.mkdir(parents=True, exist_ok=True)
        for case, counterexample in CASES.items():
            command = ["java", "-XX:+UseParallelGC", "-Xmx256m", "-Djava.rmi.server.hostname=127.0.0.1",
                       "-jar", str(jar), "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
                       "-metadir", str(scratch / case), "-config", f"WitnessNamespace-{case}.cfg",
                       "WitnessNamespace.tla"]
            log_path = logs / f"WitnessNamespace-{case}.log"
            with log_path.open("w", encoding="utf-8") as log:
                result = subprocess.run(command, cwd=BASE, stdout=log, stderr=subprocess.STDOUT,
                                        text=True, timeout=120)
            text = log_path.read_text(encoding="utf-8")
            lines = text.splitlines()
            if counterexample:
                invariant, action = counterexample
                require(result.returncode == 12 and f"Error: Invariant {invariant} is violated." in lines
                        and re.search(rf"^State \d+: <{action} line ", text, re.M),
                        f"{case}: expected {invariant} counterexample ({result.returncode})\n{text}")
                print(f"{case}: {invariant} violated by {action} (12)")
                continue
            counts = re.search(r"^\d+ states generated, (\d+) distinct states found, 0 states left on queue\.$",
                               text, re.M)
            require(result.returncode == 0 and "Model checking completed. No error has been found." in lines
                    and counts and int(counts[1]) > 0, f"{case}: incomplete safety run\n{text}")
            for action in ("RecordWitnessIntent", "LinkWitness", "ConfirmWitness", "RecordRenameIntent",
                           "SubmitRename", "RecordExpiredSuccess", "RecoverPublished", "Crash", "Reopen",
                           "ExternalCreate", "ExternalUnlink", "ExternalExtraAlias", "LoseInspection"):
                require(re.search(rf"^<{action} line .*?>: \d+:[1-9]\d*$", text, re.M),
                        f"{case}: did not explore {action}\n{text}")
            print(f"{case}: {counts[0]}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run the pinned independent retained-prefix model and its weakening controls."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
PIN = json.loads((BASE / "toolchain.lock.json").read_text())
CASES = {
    "RetainedPrefix": None,
    "RetainedPrefixEarlyPermit": "PriorEvidence",
    "RetainedPrefixPrefixWrite": "PreservedPrefix",
    "RetainedPrefixStaleCompletion": "OnlyCurrentCompletion",
    "RetainedPrefixLostBinding": "CurrentPermitBinding",
    "RetainedPrefixSkipCheckpoint": "CheckpointBeforeNextPermit",
    "RetainedPrefixStaleHead": "OnlyCurrentCompletion",
    "RetainedPrefixIgnoreMismatch": "AmbiguousCompletionBlocks",
    "RetainedPrefixSkipBudget": "CloseoutCapacityBeforePermit",
}


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def run():
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve(strict=True)
    with jar.open("rb") as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == PIN["tlc"]["sha256"],
                "TLC jar differs from owner pin")
    java = subprocess.run(["java", "-XshowSettings:properties", "-version"], capture_output=True,
                          text=True, timeout=30, check=True)
    expected = PIN["jdk"]
    props = {line.strip() for line in java.stderr.splitlines()}
    require({f"java.runtime.version = {expected['runtime_version']}",
             f"java.vendor = {expected['vendor']}"} <= props, "wrong pinned Java runtime")

    with tempfile.TemporaryDirectory(prefix="exacopy-retained-prefix-") as temporary:
        scratch = Path(temporary)
        logs = Path(os.environ.get("TLC_LOG_DIR", temporary)).resolve()
        logs.mkdir(parents=True, exist_ok=True)
        for case, invariant in CASES.items():
            command = ["java", "-XX:+UseParallelGC", "-Xmx256m", "-Djava.rmi.server.hostname=127.0.0.1",
                       "-jar", str(jar), "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
                       "-metadir", str(scratch / case), "-config", f"{case}.cfg", "RetainedPrefix.tla"]
            with (logs / f"{case}.log").open("w", encoding="utf-8") as log:
                result = subprocess.run(command, cwd=BASE, stdout=log, stderr=subprocess.STDOUT,
                                        text=True, timeout=120)
            text = (logs / f"{case}.log").read_text(encoding="utf-8")
            lines = text.splitlines()
            if invariant:
                require(result.returncode == 12 and f"Error: Invariant {invariant} is violated." in lines
                        and re.search(r"^State \d+: <(PermitTail|CompleteAt|MismatchCompletion) line ", text, re.M),
                        f"{case}: expected {invariant} counterexample\n{text}")
                print(f"{case}: {invariant} correctly violated (12)")
                continue
            counts = re.search(r"^\d+ states generated, (\d+) distinct states found, 0 states left on queue\.$",
                               text, re.M)
            require(result.returncode == 0 and "Model checking completed. No error has been found." in lines
                    and counts and int(counts[1]) > 0, f"{case}: incomplete safety run\n{text}")
            for action in ("Compare", "PrefixBarrier", "SyncedContinuation", "PermitTail", "Checkpoint", "Block", "MismatchCompletion", "ContinueWithoutTail"):
                require(re.search(rf"^<{action} line .*?>: \d+:[1-9]\d*$", text, re.M),
                        f"{case}: did not explore {action}\n{text}")
            # TLC attributes the two specialized calls to their common definition.
            complete = re.search(r"^<CompleteAt line .*?>: (\d+):\d+$", text, re.M)
            require(complete and int(complete[1]) == 2,
                    f"{case}: did not explore both distinct bounded completions\n{text}")
            print(f"{case}: {counts[0]} Two distinct tail completions reached.")


if __name__ == "__main__":
    run()

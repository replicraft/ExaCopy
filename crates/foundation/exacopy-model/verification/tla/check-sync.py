#!/usr/bin/env python3
"""Run the bounded sync model and compare its emitted classifier table."""
from hashlib import file_digest
from itertools import product
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent.parent
ROWS = HERE / "SyncBaseline.classifier.tsv"
MODEL = "SyncBaseline"
NEGATIVE = (
    ("SyncBaselineTreatUnknownAsAbsent", "UnknownPreventsInference", ()),
    ("SyncBaselineSkipReceipts", "PublicationRequiresPairedReceipts", ("PublishBaseline",)),
    ("SyncBaselineAllowStaleGeneration", "PublicationRequiresCurrentPredecessor",
     ("OtherWriterAdvances", "PublishBaseline")),
)
TABLE_ROW = re.compile(
    r'<<\s*"sync-case",\s*"([A-Za-z-]+)",\s*(TRUE|FALSE),'
    r'\s*"([A-Za-z-]+)",\s*"([A-Za-z-]+)",\s*"([a-z-]+)"\s*>>'
)
OBSERVATIONS = ("A", "B", "C", "absent", "unknown", "unsupported")
BASELINES = ("A", "B", "C", "uninitialized", "common-absent", "asymmetric")


def sha256(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def require(condition, message, log=None):
    if not condition:
        if log is not None:
            print(log, flush=True)
        raise SystemExit(message)


def check_toolchain(jar):
    lock = json.loads((HERE / "toolchain.lock.json").read_text(encoding="utf-8"))
    require(sha256(jar) == lock["tlc"]["sha256"], "TLC jar checksum mismatch")
    result = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        check=True, capture_output=True, text=True,
    )
    jdk = lock["jdk"]
    properties = {line.strip() for line in result.stderr.splitlines()}
    require(
        {f"java.runtime.version = {jdk['runtime_version']}", f"java.vendor = {jdk['vendor']}"}
        <= properties,
        f"SyncBaseline requires Temurin OpenJDK {jdk['version']}",
    )


def run_tlc(jar, scratch, logs, config):
    path = logs / f"{config}.log"
    with path.open("wb") as output:
        result = subprocess.run(
            [
                "java", "-XX:+UseParallelGC", "-Xmx256m",
                "-Djava.rmi.server.hostname=127.0.0.1", "-jar", str(jar),
                "-workers", "1", "-seed", "0", "-fp", "0", "-coverage", "1",
                "-metadir", str(scratch / config), "-config", f"{config}.cfg", f"{MODEL}.tla",
            ],
            cwd=HERE, stdout=output, stderr=subprocess.STDOUT, timeout=50,
        )
    return result.returncode, path.read_text(encoding="utf-8")


def classifier_table(log):
    rows = TABLE_ROW.findall(log)
    subjects = set(product(BASELINES, ("TRUE", "FALSE"), OBSERVATIONS, OBSERVATIONS))
    require(
        len(rows) == log.count('"sync-case"') == len(subjects)
        and {row[:4] for row in rows} == subjects,
        "TLC classifier table must enumerate each of the 432 finite subjects exactly once",
        log,
    )
    return "".join("\t".join(row) + "\n" for row in sorted(rows))


def check_positive(status, log, logs):
    counts = re.search(
        r"^[0-9]+ states generated, [0-9]+ distinct states found, 0 states left on queue\.$",
        log, re.MULTILINE,
    )
    require(
        status == 0 and counts and "Model checking completed. No error has been found." in log,
        f"SyncBaseline safety check failed (TLC exit {status})",
        log,
    )
    for action in ("Receive", "OtherWriterAdvances", "PublishBaseline"):
        require(
            re.search(rf"^<{action} line .*>: [0-9]+:[1-9][0-9]*$", log, re.MULTILINE),
            f"SyncBaseline did not explore {action}",
            log,
        )
    table = classifier_table(log)
    (logs / ROWS.name).write_text(table, encoding="ascii")
    require(
        table == ROWS.read_text(encoding="ascii"),
        f"TLC classifier table differs from the Rust replay fixture. See {logs / ROWS.name}",
    )
    print(f"SyncBaseline safety check passed. {counts[0]}")
    print("TLC reproduced all 432 classifier rows for Rust replay")


def check_negative(status, log, invariant, expected_actions):
    violation = f"Error: Invariant {invariant} is violated"
    if expected_actions:
        actions = re.findall(r"^State [0-9]+: <(\w+) line ", log, re.MULTILINE)
        # Other trace steps can appear between the required actions.
        subsequent = iter(actions)
        expected = (
            f"{violation}." in log
            and actions[-1:] == [expected_actions[-1]]
            and all(action in subsequent for action in expected_actions)
        )
    else:
        expected = f"{violation} by the initial state:" in log
    require(
        status == 12 and expected,
        f"Expected an {invariant} counterexample (TLC exit {status})",
        log,
    )
    print(f"SyncBaseline mutant violated {invariant} as expected (TLC exit {status})")
    trace = log[log.index(violation):].split("\nThe coverage statistics", 1)[0]
    print("\n".join(line for line in trace.splitlines() if not TABLE_ROW.fullmatch(line)).rstrip())


def write_bindings(logs, jar):
    inputs = [
        CRATE / "src/sync.rs",
        CRATE / "tests/sync_tlc.rs",
        CRATE / "verification/check.sh",
        HERE / "check-sync.py",
        HERE / "toolchain.lock.json",
        ROWS,
        HERE / f"{MODEL}.tla",
        *(HERE / f"{config}.cfg" for config in (MODEL, *(row[0] for row in NEGATIVE))),
    ]
    bindings = {
        "tla2tools_jar_sha256": sha256(jar),
        "crate_inputs_sha256": {
            path.relative_to(CRATE).as_posix(): sha256(path) for path in inputs
        },
    }
    report = json.dumps(bindings, indent=2, sort_keys=True)
    (logs / f"{MODEL}.inputs.json").write_text(report + "\n", encoding="utf-8")
    print(report)


def main():
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve(strict=True)
    check_toolchain(jar)
    with tempfile.TemporaryDirectory(prefix="exacopy-sync-tlc.") as temporary:
        scratch = Path(temporary)
        logs = Path(os.environ.get("TLC_LOG_DIR", temporary)).resolve()
        require(logs != HERE, "Put TLC logs outside the sync model source directory")
        logs.mkdir(parents=True, exist_ok=True)
        write_bindings(logs, jar)
        status, log = run_tlc(jar, scratch, logs, MODEL)
        check_positive(status, log, logs)
        for config, invariant, expected_actions in NEGATIVE:
            status, log = run_tlc(jar, scratch, logs, config)
            check_negative(status, log, invariant, expected_actions)


if __name__ == "__main__":
    main()

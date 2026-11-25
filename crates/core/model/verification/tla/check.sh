#!/bin/sh
set -eu

export LC_ALL=C

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

jar=${TLA2TOOLS_JAR:?Set TLA2TOOLS_JAR to the pinned TLC release jar}
case $jar in
    /*) ;;
    *) jar="$PWD/$jar" ;;
esac
model_dir=$(cd "$(dirname "$0")" && pwd -P)
python3 - "$model_dir/toolchain.lock.json" "$jar" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

lock_path, jar_path = map(Path, sys.argv[1:])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
with jar_path.open("rb") as jar:
    if hashlib.file_digest(jar, "sha256").hexdigest() != lock["tlc"]["sha256"]:
        sys.exit("TLC jar checksum mismatch")

java = subprocess.run(
    ["java", "-XshowSettings:properties", "-version"],
    check=True, capture_output=True, text=True,
)
properties = {line.strip() for line in java.stderr.splitlines()}
jdk = lock["jdk"]
if not {f"java.runtime.version = {jdk['runtime_version']}",
        f"java.vendor = {jdk['vendor']}"} <= properties:
    sys.exit(f"CopyRecovery requires Temurin OpenJDK {jdk['version']}")
PYTHON

scratch=$(mktemp -d "${TMPDIR:-/tmp}/exacopy-tlc.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
logs=${TLC_LOG_DIR:-$scratch}
mkdir -p "$logs"
logs=$(cd "$logs" && pwd -P)
cd "$model_dir"

run_tlc() {
    java -XX:+UseParallelGC -Xmx256m -Djava.rmi.server.hostname=127.0.0.1 \
        -jar "$jar" -workers 1 -seed 0 -fp 0 -coverage 1 \
        -metadir "$scratch/$1" -config "$1.cfg" CopyRecovery.tla
}

positive="$logs/CopyRecovery.log"
if ! run_tlc CopyRecovery >"$positive" 2>&1 ||
    ! grep -Fqx 'Model checking completed. No error has been found.' "$positive" ||
    ! grep -Eq '^[0-9]+ states generated, [0-9]+ distinct states found, 0 states left on queue\.$' "$positive"; then
    cat "$positive" >&2
    fail 'CopyRecovery safety check did not complete successfully'
fi

for action in DiscardLateWrite ExternalArrival ApplyNoClobber LoseReplyBeforeEffect \
    LoseReplyAfterEffect ReconcilePublished RetryAfterObservation RetryAfterCrash \
    QuiesceRetainedStage ApplyRetainedStageNoClobber ObserveRetainedStageConflict \
    ObserveConflict CommitReceipt CrashKeepingRename CrashLosingRename Restart; do
    # TLC reports counts as distinct successors attributed to this action, then all successors.
    if ! grep -Eq "^<$action line .*>: [0-9]+:[1-9][0-9]*$" "$positive"; then
        cat "$positive" >&2
        fail "CopyRecovery did not explore $action"
    fi
done

negative="$logs/CopyRecoveryEarlyPublication.log"
mutant_exit=0
run_tlc CopyRecoveryEarlyPublication >"$negative" 2>&1 || mutant_exit=$?
# TLC exit 12 denotes a state-invariant violation.
if [ "$mutant_exit" -ne 12 ] ||
    ! grep -Fqx 'Error: Invariant PriorPublicationEvidence is violated.' "$negative" ||
    ! grep -Eq '^State [0-9]+: <ApplyNoClobber line ' "$negative"; then
    cat "$negative" >&2
    fail "Expected a PriorPublicationEvidence counterexample from the mutant (TLC exit $mutant_exit)"
fi

printf '%s\n' 'CopyRecovery safety check passed'
grep -E 'states generated,|depth of the complete state graph' "$positive"
printf '%s\n' 'CopyRecovery mutant violated PriorPublicationEvidence as expected'
grep -E '^State [0-9]+:|states generated,' "$negative"

retry_negative="$logs/CopyRecoveryUnverifiedRetry.log"
mutant_exit=0
run_tlc CopyRecoveryUnverifiedRetry >"$retry_negative" 2>&1 || mutant_exit=$?
if [ "$mutant_exit" -ne 12 ] ||
    ! grep -Fqx 'Error: Invariant PriorPublicationEvidence is violated.' "$retry_negative" ||
    ! grep -Eq '^State [0-9]+: <RetryAfter(Observation|Crash) line ' "$retry_negative" ||
    ! grep -Eq '^State [0-9]+: <ApplyRetainedStageNoClobber line ' "$retry_negative"; then
    cat "$retry_negative" >&2
    fail "Expected a PriorPublicationEvidence counterexample during retained-stage retry (TLC exit $mutant_exit)"
fi

printf '%s\n' 'CopyRecovery unverified retry mutant violated PriorPublicationEvidence as expected'
# The evidence recorder keeps the original negative control separately.
sed -n '/^Error: Invariant /,/^The coverage statistics/{ /^The coverage statistics/!p; }' "$retry_negative"
grep -E 'states generated,' "$retry_negative"

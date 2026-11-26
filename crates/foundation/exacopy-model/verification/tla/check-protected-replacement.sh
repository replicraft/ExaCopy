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
python3 - "$model_dir/toolchain.lock.json" "$jar" <<'PY'
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
    sys.exit(f"ProtectedReplacement requires Temurin OpenJDK {jdk['version']}")
PY

scratch=$(mktemp -d "${TMPDIR:-/tmp}/exacopy-protected-tlc.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
logs=${TLC_LOG_DIR:-$scratch}
mkdir -p "$logs"
logs=$(cd "$logs" && pwd -P)
cd "$model_dir"

run_tlc() {
    java -XX:+UseParallelGC -Xmx256m -Djava.rmi.server.hostname=127.0.0.1 \
        -jar "$jar" -workers 1 -seed 0 -fp 0 -coverage 1 \
        -metadir "$scratch/$1" -config "$1.cfg" ProtectedReplacement.tla
}

positive="$logs/ProtectedReplacement.log"
if ! run_tlc ProtectedReplacement >"$positive" 2>&1 ||
    ! grep -Fqx 'Model checking completed. No error has been found.' "$positive" ||
    ! grep -Eq '^[0-9]+ states generated, [0-9]+ distinct states found, 0 states left on queue\.$' "$positive"; then
    cat "$positive" >&2
    fail 'ProtectedReplacement safety check did not complete'
fi

for action in RejectHistoricalAdmission RebindBeforeCapture OccupyPrivateSlot CaptureActual CaptureBlocked \
    LatePublicArrival SyncPublic SyncPrivate PostBarrierObservation CommitCaptureEvidence \
    RefuseWrongObservation VerifyIndependentImage RefuseImage GrantPublication PlaceStage \
    PublicationConflict LoseReplyBeforeEffect Interrupt; do
    if ! grep -Eq "^<$action line .*>: [0-9]+:[1-9][0-9]*$" "$positive"; then
        cat "$positive" >&2
        fail "ProtectedReplacement did not explore $action"
    fi
done

check_mutant() {
    config=ProtectedReplacement$1
    invariant=$2
    action=$3
    log="$logs/$config.log"
    result=0
    run_tlc "$config" >"$log" 2>&1 || result=$?
    if [ "$result" -ne 12 ] ||
        ! grep -Fqx "Error: Invariant $invariant is violated." "$log" ||
        ! grep -Eq "^State [0-9]+: <$action line " "$log"; then
        cat "$log" >&2
        fail "Expected $config to violate $invariant at $action; exit $result"
    fi
    printf '%s violated %s as expected\n' "$config" "$invariant"
}

printf '%s\n' 'ProtectedReplacement safety check passed'
grep -E 'states generated,|depth of the complete state graph' "$positive"
check_mutant CapturePrior ActualEntryRetained CaptureActual
check_mutant SkipPublicBarrier PublicationRequiresDurableApprovedCapture GrantPublication
check_mutant SkipPrivateBarrier PublicationRequiresDurableApprovedCapture GrantPublication
check_mutant AllowForeign PublicationRequiresDurableApprovedCapture GrantPublication
check_mutant TrustPost PublicationRequiresDurableApprovedCapture GrantPublication
check_mutant SkipImage PublicationRequiresDurableApprovedCapture GrantPublication
check_mutant ClobberArrival NoPublicClobber PlaceStage
check_mutant RetryUnknown OneShot RetryUnknown
check_mutant AdmitPriorHistory FreshAdmission RecordCaptureIntent

#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$verification_dir/../../../.." && pwd -P)

check_rust() (
	cd "$repo"
	cargo nextest run --locked -p exacopy-diff --profile ci
)

check_tlc() (
	jar=${TLA2TOOLS_JAR:?Set TLA2TOOLS_JAR to the pinned TLC release jar}
	case $jar in
		/*) ;;
		*) jar="$PWD/$jar" ;;
	esac
	python3 - "$verification_dir/tla/toolchain.lock.json" "$jar" <<'PY'
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
    ["java", "-XshowSettings:properties", "-version"], check=True, capture_output=True, text=True
)
properties = {line.strip() for line in java.stderr.splitlines()}
jdk = lock["jdk"]
if not {f"java.runtime.version = {jdk['runtime_version']}",
        f"java.vendor = {jdk['vendor']}"} <= properties:
    sys.exit(f"ParallelCompare requires Temurin OpenJDK {jdk['version']}")
PY

	scratch=$(mktemp -d "${TMPDIR:-/tmp}/exacopy-diff-tlc.XXXXXX")
	trap 'rm -rf "$scratch"' EXIT
	trap 'exit 1' HUP INT TERM
	logs=${TLC_LOG_DIR:-$scratch}
	mkdir -p "$logs"
	logs=$(cd "$logs" && pwd -P)
	cd "$verification_dir/tla"

	run_tlc() {
		java -XX:+UseParallelGC -Xmx256m -Djava.rmi.server.hostname=127.0.0.1 \
			-jar "$jar" -workers 1 -seed 0 -fp 0 -metadir "$scratch/$1" \
			-config "$1.cfg" ParallelCompare.tla
	}

	positive="$logs/ParallelCompare.log"
	if ! run_tlc ParallelCompare >"$positive" 2>&1 ||
		! grep -Fqx 'Model checking completed. No error has been found.' "$positive" ||
		! grep -Eq '^[0-9]+ states generated, [0-9]+ distinct states found, 0 states left on queue\.$' "$positive"; then
		cat "$positive" >&2
		exit 1
	fi
	grep -E 'states generated,|depth of the complete state graph' "$positive"

	negative="$logs/ParallelCompareEarlyReturn.log"
	status=0
	run_tlc ParallelCompareEarlyReturn >"$negative" 2>&1 || status=$?
	if [ "$status" -ne 12 ] ||
		! grep -Fqx 'Error: Invariant AllJoinedAtReturn is violated.' "$negative"; then
		cat "$negative" >&2
		exit 1
	fi
	grep -F 'Error: Invariant AllJoinedAtReturn is violated.' "$negative"
)

case ${1:-all} in
	rust) check_rust ;;
	tlc) check_tlc ;;
	all)
		status=0
		"$verification_dir/check.sh" rust || status=1
		"$verification_dir/check.sh" tlc || status=1
		exit "$status"
		;;
	*)
		printf '%s\n' 'usage: check.sh [rust|tlc|all]' >&2
		exit 2
		;;
esac

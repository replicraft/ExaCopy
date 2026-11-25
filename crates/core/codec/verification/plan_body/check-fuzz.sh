#!/usr/bin/env bash
set -euo pipefail

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/../../../../.." && pwd -P)
cd -- "$workspace"
if (( $# > 1 )); then
	printf 'Usage: check-fuzz.sh [new evidence directory]\n' >&2
	exit 2
fi
if (( $# == 1 )); then
	mkdir -- "$1"
	run_dir=$(CDPATH='' cd -- "$1" && pwd -P)
else
	run_dir=$(mktemp -d "${TMPDIR:-/tmp}/exacopy-plan-body-fuzz.XXXXXX")
fi
mkdir -p "$run_dir/corpus" "$run_dir/crashes" "$run_dir/bound-seeds"
printf 'Evidence directory: %s\n' "$run_dir"

fuzz_dir="$workspace/crates/core/codec/fuzz"
target=plan_body
toolchain=nightly-2026-11-04
RUSTC=$(rustup which --toolchain "$toolchain" rustc)
export RUSTC PATH="$(dirname "$RUSTC"):$PATH" CARGO_NET_OFFLINE=true
host=$("$RUSTC" -vV | awk '$1 == "host:" { print $2 }')
seed=441038
runs=250000
max_len=1048577
wall_limit=90
timeout=2
rss_limit=768

{
	printf 'Rust toolchain: %s\n' "$toolchain"
	"$RUSTC" -vV
	cargo -V
	fuzz_version=$(cargo fuzz --version)
	printf '%s\n' "$fuzz_version"
	[[ "$fuzz_version" == 'cargo-fuzz 0.13.2' ]]
	uname -srm
	printf 'Sanitizer: address\nSeed: %s\nInputs: %s\nMax input bytes: %s\nWall limit seconds: %s\nInput timeout seconds: %s\nRSS limit MiB: %s\n' \
		"$seed" "$runs" "$max_len" "$wall_limit" "$timeout" "$rss_limit"
} > "$run_dir/toolchain-and-budget.txt"

python3 - "$run_dir/bound-seeds" "$max_len" <<'PY'
from pathlib import Path
import sys

seed_dir, bytes_over_limit = Path(sys.argv[1]), int(sys.argv[2])
seed_dir.joinpath("over-plan-body-byte-limit").write_bytes(bytes(bytes_over_limit))
PY

hash_inputs() {
	python3 - "$workspace" "$run_dir" <<'PY'
import hashlib
from pathlib import Path
import sys

workspace, run = map(Path, sys.argv[1:])
codec = workspace / "crates/core/codec"
fuzz = codec / "fuzz"
verification = codec / "verification/plan_body"
files = [
    workspace / "Cargo.toml", workspace / "Cargo.lock",
    codec / "Cargo.toml", fuzz / "Cargo.toml", fuzz / "Cargo.lock",
    verification / "check-fuzz.sh",
    *verification.joinpath("vectors").iterdir(),
    *codec.joinpath("src").rglob("*.rs"),
    *fuzz.joinpath("fuzz_targets").glob("*.rs"),
    *fuzz.joinpath("corpus/plan_body").iterdir(),
]
for file in sorted(files):
    print(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.relative_to(workspace)}")
for file in sorted(run.joinpath("bound-seeds").iterdir()):
    print(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.relative_to(run)}")
PY
}
hash_inputs > "$run_dir/inputs-before.sha256"
cargo metadata --locked --manifest-path "$fuzz_dir/Cargo.toml" \
	--format-version 1 > "$run_dir/metadata.json"

set +e
cargo fuzz run --fuzz-dir "$fuzz_dir" --target-dir "$run_dir/target" --target "$host" \
	--sanitizer address "$target" "$run_dir/corpus" "$fuzz_dir/corpus/$target" "$run_dir/bound-seeds" \
	-- -seed="$seed" -runs="$runs" -max_len="$max_len" -max_total_time="$wall_limit" \
	-timeout="$timeout" -rss_limit_mb="$rss_limit" -artifact_prefix="$run_dir/crashes/" \
	2>&1 | tee "$run_dir/fuzz-engine.log"
status=("${PIPESTATUS[@]}")
set -e

hash_inputs > "$run_dir/inputs-after.sha256"
printf '%s\n' "${status[0]}" > "$run_dir/exit-status.txt"
cmp "$run_dir/inputs-before.sha256" "$run_dir/inputs-after.sha256"
(( status[1] == 0 )) || exit "${status[1]}"
(( status[0] == 0 )) || exit "${status[0]}"
grep -Eq "^Done $runs runs in " "$run_dir/fuzz-engine.log"
test -z "$(find "$run_dir/crashes" -type f -print -quit)"
nm "$run_dir/target/$host/release/$target" > "$run_dir/symbols.txt"
grep -E '(__asan_init|__asan_report_(load|store))' "$run_dir/symbols.txt" > "$run_dir/asan-symbols.txt"

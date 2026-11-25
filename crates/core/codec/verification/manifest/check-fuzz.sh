#!/usr/bin/env bash
set -euo pipefail

workspace=$(
	CDPATH='' cd -- "$(dirname -- "$0")/../../../../.." && pwd -P
)
cd -- "$workspace"

if (( $# > 1 )); then
	printf 'Usage: check-fuzz.sh [new evidence directory]\n' >&2
	exit 2
fi
if (( $# == 1 )); then
	mkdir -- "$1"
	run_dir=$(CDPATH='' cd -- "$1" && pwd -P)
else
	run_dir=$(mktemp -d "${TMPDIR:-/tmp}/exacopy-manifest-fuzz.XXXXXX")
fi
mkdir -p "$run_dir/corpus" "$run_dir/crashes"
printf 'Evidence directory: %s\n' "$run_dir"

fuzz_dir="$workspace/crates/core/codec/fuzz"
toolchain=nightly-2026-11-04
nightly_rustc=$(rustup which --toolchain "$toolchain" rustc)
export PATH="$(dirname "$nightly_rustc"):$PATH"
export RUSTC="$nightly_rustc"
export CARGO_NET_OFFLINE=true

seed=18723
runs=250000
max_len=16385
max_total_time=90
timeout=2
rss_limit_mb=768

{
	printf 'Rust toolchain: %s\n' "$toolchain"
	"$RUSTC" -vV
	cargo -V
	fuzz_version=$(cargo fuzz --version)
	printf '%s\n' "$fuzz_version"
	if [[ "$fuzz_version" != 'cargo-fuzz 0.13.2' ]]; then
		printf 'Expected cargo-fuzz 0.13.2.\n' >&2
		exit 1
	fi
	uname -srm
	printf 'Sanitizer: address\nSeed: %s\nInputs: %s\nMax input bytes: %s\nWall limit seconds: %s\nInput timeout seconds: %s\nRSS limit MiB: %s\n' \
		"$seed" "$runs" "$max_len" "$max_total_time" "$timeout" "$rss_limit_mb"
} > "$run_dir/toolchain-and-budget.txt"

hash_inputs() {
	python3 - "$workspace" <<'PY'
import hashlib
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
codec = workspace / "crates/core/codec"
fuzz = codec / "fuzz"
files = [
    workspace / "Cargo.toml",
    workspace / "Cargo.lock",
    codec / "Cargo.toml",
    codec / "verification/manifest/check-fuzz.sh",
    fuzz / "Cargo.toml",
    fuzz / "Cargo.lock",
    *codec.joinpath("src").rglob("*.rs"),
    *fuzz.joinpath("fuzz_targets").glob("*.rs"),
    *fuzz.joinpath("corpus/manifest_json").iterdir(),
]
for file in sorted(files):
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    print(f"{digest}  {file.relative_to(workspace)}")
PY
}

hash_inputs > "$run_dir/inputs-before.sha256"
cargo metadata --locked --manifest-path "$fuzz_dir/Cargo.toml" \
	--format-version 1 > "$run_dir/metadata.json"

set +e
cargo fuzz run --fuzz-dir "$fuzz_dir" --target-dir "$run_dir/target" \
	--sanitizer address manifest_json "$run_dir/corpus" "$fuzz_dir/corpus/manifest_json" \
	-- -seed="$seed" -runs="$runs" -max_len="$max_len" -max_total_time="$max_total_time" \
	-timeout="$timeout" -rss_limit_mb="$rss_limit_mb" \
	-artifact_prefix="$run_dir/crashes/" 2>&1 | tee "$run_dir/fuzz-engine.log"
status=("${PIPESTATUS[@]}")
set -e

hash_inputs > "$run_dir/inputs-after.sha256"
printf '%s\n' "${status[0]}" > "$run_dir/exit-status.txt"
cmp "$run_dir/inputs-before.sha256" "$run_dir/inputs-after.sha256"
if (( status[1] != 0 )); then
	exit "${status[1]}"
fi
if (( status[0] != 0 )); then
	exit "${status[0]}"
fi
if ! grep -Eq "^Done $runs runs in " "$run_dir/fuzz-engine.log"; then
	printf 'The fuzzer did not complete the %s-input budget.\n' "$runs" >&2
	exit 1
fi

#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=.github/ci/common.sh
source "$(dirname "$0")/common.sh"

target=${1:-unix_component}
case "$target" in
	unix_component)
		fuzz_dir="$PWD/crates/foundation/exacopy-core/fuzz"
		campaign_limits=(-max_total_time=15)
		;;
	journal_frame)
		fuzz_dir="$PWD/crates/storage/exacopy-journal/fuzz"
		campaign_limits=(-max_total_time=45 -rss_limit_mb=768)
		;;
	*)
		printf 'Usage: fuzz.sh [unix_component|journal_frame]\n' >&2
		exit 2
		;;
esac

temp_dir=$(runner_temp)
run_dir=$(mktemp -d "$temp_dir/exacopy-fuzz.XXXXXX")
evidence="$temp_dir/exacopy-evidence"
crashes="$evidence/fuzz-crashes"
report="$evidence/fuzz-engine.log"
mkdir -p "$run_dir/corpus" "$crashes"

fuzz_lock="$fuzz_dir/Cargo.lock"
fuzz_before=$(hash_stream < "$fuzz_lock")
workspace_before=$(hash_stream < Cargo.lock)
printf 'fuzz lockfile SHA-256 before: %s\nworkspace lockfile SHA-256 before: %s\n' \
	"$fuzz_before" "$workspace_before"

nightly_rustc=$(rustup which --toolchain nightly-2026-11-04 rustc)
nightly_bin=$(dirname "$nightly_rustc")
export PATH="$nightly_bin:$PATH"
export RUSTC="$nightly_rustc"
"$RUSTC" -vV
cargo -V
cargo fuzz --version
cargo metadata --locked --manifest-path "$fuzz_dir/Cargo.toml" --format-version 1 >/dev/null

runs=250000
set +e
CARGO_NET_OFFLINE=true cargo fuzz run --fuzz-dir "$fuzz_dir" --target-dir "$run_dir/target" \
	--sanitizer address "$target" "$run_dir/corpus" "$fuzz_dir/corpus/$target" \
	-- -seed=18723 -runs="$runs" -max_len=512 -timeout=2 "${campaign_limits[@]}" \
	-artifact_prefix="$crashes/" 2>&1 | tee "$report"
status=("${PIPESTATUS[@]}")
set -e

fuzz_after=$(hash_stream < "$fuzz_lock")
workspace_after=$(hash_stream < Cargo.lock)
printf 'fuzz lockfile SHA-256 after: %s\nworkspace lockfile SHA-256 after: %s\n' \
	"$fuzz_after" "$workspace_after"
printf 'fuzzer exit status: %s\n' "${status[0]}"
if [[ "$fuzz_before" != "$fuzz_after" || "$workspace_before" != "$workspace_after" ]]; then
	printf 'A lockfile changed during the fuzz campaign.\n' >&2
	exit 1
fi
if (( status[1] != 0 )); then
	exit "${status[1]}"
fi
if (( status[0] != 0 )); then
	exit "${status[0]}"
fi
if ! grep -Eq "^Done $runs runs in " "$report"; then
	printf 'The fuzzer did not report completing %s inputs.\n' "$runs" >&2
	exit 1
fi

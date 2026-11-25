#!/usr/bin/env bash
set -euo pipefail

kani_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
read -r kani_version toolchain rust_revision cbmc_version < <(
	python3 - "$kani_dir/toolchain.lock.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    pin = json.load(file)
print(pin["kani"]["version"], pin["rust"]["toolchain"],
      pin["rust"]["source_revision"], pin["cbmc"]["version"])
PY
)

cargo=(rustup run "$toolchain" cargo)
rust_version=$(rustup run "$toolchain" rustc --version --verbose)
if ! grep -Fxq "commit-hash: $rust_revision" <<< "$rust_version"; then
	printf 'Unexpected Kani Rust compiler. Expected revision %s.\n' "$rust_revision" >&2
	exit 1
fi
target=$(awk '/^host: / { print $2 }' <<< "$rust_version")
kani_info=$("${cargo[@]}" kani --version --verbose)
printf '%s\n' "$kani_info"
if ! grep -Fxq "Kani Rust Verifier $kani_version (kani-$kani_version) (cargo plugin)" <<< "$kani_info" ||
	! grep -Fq "using rustc $(rustup run "$toolchain" rustc --version | cut -d ' ' -f 2-)" <<< "$kani_info" ||
	! grep -Fxq "CBMC $cbmc_version" <<< "$kani_info"; then
	printf 'Kani, its compiler, or CBMC does not match toolchain.lock.json.\n' >&2
	exit 1
fi

workspace=$("${cargo[@]}" locate-project --workspace --message-format plain \
	--manifest-path "$kani_dir/../../Cargo.toml")
cd "$(dirname "$workspace")"
lock_before=$(LC_ALL=C shasum -a 256 Cargo.lock)
"${cargo[@]}" fetch --locked --target "$target"
CARGO_NET_OFFLINE=true "${cargo[@]}" metadata --locked --format-version 1 \
	--filter-platform "$target" > /dev/null

harness=kani_checks::range::checked_range_end_matches_wide_arithmetic
kani_log=$(mktemp "${TMPDIR:-/tmp}/exacopy-kani-log.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
kani_status=0
# Kani keeps assertion reachability and CBMC's unwinding assertions enabled by default.
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-model --harness "$harness" \
	--exact --default-unwind 1 --output-format regular 2>&1 | tee "$kani_log" || kani_status=$?

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf 'Cargo.lock changed during Kani verification.\n' >&2
	exit 1
fi
if (( kani_status != 0 )); then
	exit "$kani_status"
fi
if ! grep -Fxq 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.' "$kani_log" ||
	! grep -Eq '^[[:space:]]*\*\* 6 of 6 cover properties satisfied$' "$kani_log" ||
	! awk '
		/- Status: SUCCESS$/ { success_line = NR }
		/- Description: "range admission and end match wide arithmetic"$/ && success_line == NR - 1 {
			found = 1
		}
		END { exit !found }
	' "$kani_log"; then
	printf 'Kani did not verify the range assertion and all six reachability goals.\n' >&2
	exit 1
fi

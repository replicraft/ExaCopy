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

range=kani_checks::range::checked_range_end_matches_wide_arithmetic
clock=kani_checks::grant_time::grant_time_matches_wide_nanosecond_specification
kani_log=$(mktemp "${EXACOPY_VERIFICATION_SCRATCH:-${TMPDIR:-/tmp}}/exacopy-kani-log.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
kani_status=0
# Kani keeps assertion reachability and CBMC's unwinding assertions enabled by default.
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-model --exact \
	--harness "$range" --harness "$clock" --default-unwind 1 --output-format regular \
	2>&1 | tee "$kani_log" || kani_status=$?

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf 'Cargo.lock changed during Kani verification.\n' >&2
	exit 1
fi
if (( kani_status != 0 )); then
	exit "$kani_status"
fi
if ! grep -Fxq 'Complete - 2 successfully verified harnesses, 0 failures, 2 total.' "$kani_log" ||
	! awk -v range="$range" -v clock="$clock" '
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
			seen[active]++
			if (active != range && active != clock) wrong = 1
		}
		/^  - (Verified stub|Stub): / { wrong = 1 }
		/- Status: SUCCESS$/ { success_line = NR }
		success_line == NR - 1 {
			if (active == range && /- Description: "range admission and end match wide arithmetic"$/) range_assert++
			if (active == clock && /- Description: "grant time matches the independent wide UTC specification"$/) clock_assert++
			if (active == clock && /- Description: "qualification cannot widen clock admission"$/) subset_assert++
		}
		active == range && /^[[:space:]]*\*\* 6 of 6 cover properties satisfied$/ { range_covers++ }
		active == clock && /^[[:space:]]*\*\* 12 of 12 cover properties satisfied$/ { clock_covers++ }
		END {
			exit (wrong || seen[range] != 1 || seen[clock] != 1 || range_assert != 1 ||
				clock_assert != 1 || subset_assert != 1 || range_covers != 1 || clock_covers != 1)
		}
	' "$kani_log"; then
	printf '%s\n' 'Expected both model Kani harnesses, three assertions and eighteen reached covers.' >&2
	exit 1
fi

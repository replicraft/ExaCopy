#!/usr/bin/env bash
set -euo pipefail

case "$#:${1-}" in
	0:) gate=range ;;
	1:--grant-time) gate=clock ;;
	*) printf 'usage: check.sh [--grant-time]\n' >&2; exit 2 ;;
esac

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
contract=kani_checks::grant_time::real_utc_before_matches_wide_nanosecond_order
clock=kani_checks::grant_time::grant_time_matches_wide_nanosecond_specification
if [[ "$gate" == range ]]; then
	selection=(--harness "$range")
else
	selection=(--harness "$contract" --harness "$clock")
fi
kani_log=$(mktemp "${EXACOPY_VERIFICATION_SCRATCH:-${TMPDIR:-/tmp}}/exacopy-kani-log.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
kani_status=0
# Both proof lanes compile the same annotated owner crate. Only the clock
# composition selects a verified stub, and ordinary calls retain their bodies.
# Preserve default assertion reachability and unwinding checks.
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-model --exact \
	"${selection[@]}" --default-unwind 1 --output-format regular \
	-Z unstable-options -Z function-contracts -Z stubbing --no-assert-contracts \
	2>&1 | tee "$kani_log" || kani_status=$?

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf 'Cargo.lock changed during Kani verification.\n' >&2
	exit 1
fi
if (( kani_status != 0 )); then
	exit "$kani_status"
fi
if [[ "$gate" == range ]]; then
	total=1
else
	total=2
fi
if ! grep -Fxq "Complete - $total successfully verified harnesses, 0 failures, $total total." "$kani_log" ||
	! awk -v gate="$gate" -v range="$range" -v contract="$contract" -v clock="$clock" '
		BEGIN {
			if (gate == "range") selected[range] = 6
			else {
				selected[contract] = 4
				selected[clock] = 12
			}
		}
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
			seen[active]++
			if (!(active in selected)) wrong = 1
		}
		/^  - (Verified stub|Stub): / {
			if (gate == "clock" && active == clock &&
			    $0 == "  - Verified stub: exacopy_model::grant_time::before") verified++
			else wrong = 1
		}
		/- Status: SUCCESS$/ { success_line = NR }
		success_line == NR - 1 {
			if (active == range && /- Description: "range admission and end match wide arithmetic"$/) range_assert++
			if (active == contract && /- Description: "the real UTC comparator matches the exact wide delta order"$/) contract_assert++
			if (active == clock && /- Description: "grant time matches the independent wide UTC specification"$/) clock_assert++
			if (active == clock && /- Description: "qualification cannot widen clock admission"$/) subset_assert++
		}
		active in selected && /^[[:space:]]*\*\* [0-9]+ of [0-9]+ cover properties satisfied$/ {
			expected = "** " selected[active] " of " selected[active] " cover properties satisfied"
			sub(/^[[:space:]]*/, "")
			if ($0 != expected) wrong = 1
			covered[active]++
		}
		END {
			for (harness in selected) if (seen[harness] != 1 || covered[harness] != 1) wrong = 1
			if (gate == "range") exit (wrong || range_assert != 1)
			exit (wrong || verified != 1 || contract_assert != 1 || clock_assert != 1 || subset_assert != 1)
		}
	' "$kani_log"; then
	printf 'Expected the exact model Kani %s harnesses, substitutions, assertions and covers.\n' "$gate" >&2
	exit 1
fi

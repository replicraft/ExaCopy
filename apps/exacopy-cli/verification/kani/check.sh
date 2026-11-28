#!/usr/bin/env bash
set -euo pipefail

kani_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$kani_dir/../../../.." && pwd -P)
lock="$repo/crates/foundation/exacopy-model/verification/kani/toolchain.lock.json"
read -r kani_version toolchain rust_revision cbmc_version < <(
	python3 - "$lock" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    pin = json.load(file)
print(pin["kani"]["version"], pin["rust"]["toolchain"],
      pin["rust"]["source_revision"], pin["cbmc"]["version"])
PY
)

cargo=(rustup run "$toolchain" cargo)
target=x86_64-unknown-linux-gnu
if (( $# != 3 )) || [[ "$1" != --no-default-features || "$2" != --features ]]; then
	printf '%s\n' 'Local apply Kani needs the explicitly recorded no-default feature selection.' >&2
	exit 2
fi
feature=$(python3 - "$kani_dir/../obligations.toml" "$3" <<'PYPROFILE'
import sys
import tomllib

with open(sys.argv[1], "rb") as ledger:
    obligations = tomllib.load(ledger)["obligation"]
entries = [entry for entry in obligations if entry["id"] == "P-082"]
if len(entries) != 1 or "kani" not in entries[0]["gates"]:
    sys.exit("Local apply Kani expects one declared P-082 Kani gate.")
features = entries[0]["kani"].get("features", [])
if features != ["experimental-linux-public-apply"] or ",".join(features) != sys.argv[2]:
    sys.exit("Requested features differ from the exact selected P-082 local apply profile.")
print(",".join(features))
PYPROFILE
)
rust_info=$(rustup run "$toolchain" rustc --version --verbose)
if ! grep -Fxq "host: $target" <<< "$rust_info" ||
	! grep -Fxq "commit-hash: $rust_revision" <<< "$rust_info"; then
	printf '%s\n' 'Local apply Kani requires the pinned x86-64 Linux compiler.' >&2
	exit 1
fi
kani_info=$("${cargo[@]}" kani --version --verbose)
printf '%s\n' "$kani_info"
if ! grep -Fxq "Kani Rust Verifier $kani_version (kani-$kani_version) (cargo plugin)" <<< "$kani_info" ||
	! grep -Fq "using ${rust_info%%$'\n'*}" <<< "$kani_info" ||
	! grep -Fxq "CBMC $cbmc_version" <<< "$kani_info"; then
	printf '%s\n' 'Kani, rustc or CBMC differs from the workspace verification lock.' >&2
	exit 1
fi

cd "$repo"
lock_before=$(LC_ALL=C shasum -a 256 Cargo.lock)
"${cargo[@]}" fetch --locked --target "$target"
CARGO_NET_OFFLINE=true "${cargo[@]}" metadata --locked --format-version 1 \
	--filter-platform "$target" --manifest-path apps/exacopy-cli/Cargo.toml \
	--no-default-features --features "$feature" > /dev/null

window=kani_checks::local_apply::grant_window_matches_full_width_interval
phase=kani_checks::local_apply::grant_phase_matches_closed_effect_relation
printf 'Local apply Kani package exacopy-cli host %s opt-in feature %s (no default features)\n' "$target" "$feature"
kani_log=$(mktemp "${EXACOPY_VERIFICATION_SCRATCH:-${TMPDIR:-/tmp}}/exacopy-local-apply-kani.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
set +e
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-cli --lib --exact \
	--no-default-features --features "$feature" --harness "$window" --harness "$phase" \
	--output-format regular -Z unstable-options --harness-timeout 300s 2>&1 | tee "$kani_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf '%s\n' 'Cargo.lock changed during local apply Kani verification.' >&2
	exit 1
fi
if (( pipeline_status[1] != 0 || pipeline_status[0] != 0 )); then
	printf 'Local apply Kani exit %s, log exit %s.\n' "${pipeline_status[@]}" >&2
	if (( pipeline_status[1] != 0 )); then
		exit "${pipeline_status[1]}"
	fi
	exit "${pipeline_status[0]}"
fi

if ! grep -Fxq 'Complete - 2 successfully verified harnesses, 0 failures, 2 total.' "$kani_log" ||
	! awk -v window="$window" -v phase="$phase" '
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
			seen[active]++
			if (active != window && active != phase) wrong = 1
		}
		/^  - (Verified stub|Stub): / { wrong = 1 }
		/- Status: SUCCESS$/ { success_line = NR }
		success_line == NR - 1 {
			if (active == window && /- Description: "grant window matches the independent wide interval"$/) window_assert++
			if (active == phase && /- Description: "grant phase input observes its exact symbolic payload"$/) input_assert++
			if (active == phase && /- Description: "grant phase and payload match the independent effect relation"$/) phase_assert++
		}
		active == window && /^[[:space:]]*\*\* 6 of 6 cover properties satisfied$/ { window_covers++ }
		active == phase && /^[[:space:]]*\*\* 13 of 13 cover properties satisfied$/ { phase_covers++ }
		END {
			exit (wrong || seen[window] != 1 || seen[phase] != 1 || window_assert != 1 ||
				input_assert != 1 || phase_assert != 1 || window_covers != 1 || phase_covers != 1)
		}
	' "$kani_log"; then
	printf '%s\n' 'Expected exactly both local apply Kani harnesses, assertions and nineteen covers.' >&2
	exit 1
fi

printf 'EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features %s\n' "$feature"

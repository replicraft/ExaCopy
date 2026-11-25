#!/usr/bin/env bash
set -euo pipefail

kani_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
toolchain_lock="$kani_dir/../../../../core/model/verification/kani/toolchain.lock.json"
read -r kani_version toolchain rust_revision cbmc_version supported_targets < <(
	python3 - "$toolchain_lock" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    pin = json.load(file)
print(pin["kani"]["version"], pin["rust"]["toolchain"],
      pin["rust"]["source_revision"], pin["cbmc"]["version"],
      *pin["kani"]["archives"])
PY
)

cargo=(rustup run "$toolchain" cargo)
rust_info=$(rustup run "$toolchain" rustc --version --verbose)
target=$(awk '/^host: / { print $2 }' <<< "$rust_info")
if [[ -z "$target" || " $supported_targets " != *" $target "* ]] ||
	! grep -Fxq "commit-hash: $rust_revision" <<< "$rust_info"; then
	printf 'Kani Rust target or compiler does not match the workspace verification lock.\n' >&2
	exit 1
fi
kani_info=$("${cargo[@]}" kani --version --verbose)
printf '%s\n' "$kani_info"
if ! grep -Fxq "Kani Rust Verifier $kani_version (kani-$kani_version) (cargo plugin)" <<< "$kani_info" ||
	! grep -Fq "using ${rust_info%%$'\n'*}" <<< "$kani_info" ||
	! grep -Fxq "CBMC $cbmc_version" <<< "$kani_info"; then
	printf 'Kani, its compiler, or CBMC does not match the workspace verification lock.\n' >&2
	exit 1
fi

workspace=$("${cargo[@]}" locate-project --workspace --message-format plain \
	--manifest-path "$kani_dir/../../Cargo.toml")
cd "$(dirname "$workspace")"
lock_before=$(LC_ALL=C shasum -a 256 Cargo.lock)
"${cargo[@]}" fetch --locked --target "$target"
CARGO_NET_OFFLINE=true "${cargo[@]}" metadata --locked --format-version 1 \
	--filter-platform "$target" > /dev/null

primary=kani_checks::component::checked_unix_component_matches_byte_specification
oversize=kani_checks::component::oversized_unix_component_at_first_invalid_length
kani_log=$(mktemp "${TMPDIR:-/tmp}/exacopy-core-kani.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
kani_status=0
# Kani keeps assertion reachability and CBMC's unwinding assertions enabled by default.
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-core --lib --exact \
	--harness "$primary" --harness "$oversize" --output-format regular \
	-Z unstable-options --harness-timeout 300s 2>&1 | tee "$kani_log" || kani_status=$?

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf 'Cargo.lock changed during Kani verification.\n' >&2
	exit 1
fi
if (( kani_status != 0 )); then
	exit "$kani_status"
fi
if ! grep -Fxq 'Complete - 2 successfully verified harnesses, 0 failures, 2 total.' "$kani_log" ||
	! grep -Eq '^[[:space:]]*\*\* 7 of 7 cover properties satisfied$' "$kani_log" ||
	! grep -Eq '^[[:space:]]*\*\* 1 of 1 cover properties satisfied$' "$kani_log" ||
	! awk '
		/- Status: SUCCESS$/ { success_line = NR }
		success_line != NR - 1 { next }
		/- Description: "validation matches the Unix byte specification"$/ { validation = 1 }
		/- Description: "accepted name borrows its original bytes"$/ { identity = 1 }
		/- Description: "every 256-byte name is oversized"$/ { oversize = 1 }
		END { exit !(validation && identity && oversize) }
	' "$kani_log"; then
	printf 'Kani did not verify both Unix component harnesses and all eight reachability goals.\n' >&2
	exit 1
fi

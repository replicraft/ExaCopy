#!/usr/bin/env bash
set -euo pipefail

kani_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
toolchain_lock="$kani_dir/../../../../foundation/exacopy-model/verification/kani/toolchain.lock.json"
mutation=${1:-}
if (( $# > 1 )) || { (( $# == 1 )) && [[ -z "$mutation" ]]; }; then
	exit 2
fi
case "$mutation" in
	'') ;;
	lease-clipping)
		harness='kani_checks::connection_retry::lease_and_revocation_bound_waiting_and_redial'
		assertion='the lease clips the jittered wake exactly at expiry'
		expected_source='c45bf829c5f5d85c150d03bcb153ca14c39e5080ca6648369e7068ab59c24bea'
		;;
	source-fence)
		harness='kani_checks::connection_retry::reconnect_requires_current_route_ssh_and_source_and_fences_retired_work'
		assertion='every independent observation must refer to the current attempt'
		expected_source='f2a6173975a8b48abe8d08cc48819a545613fd8683aa2bc3a3795e1aa10c98bc'
		;;
	health-activity)
		harness='kani_checks::connection_retry::penalty_resets_only_after_current_verified_activity_and_health'
		assertion='reset requires both qualifying activity and the full healthy duration'
		expected_source='a003d5eded1906a919b58b34c834c4496d17665a971d04b1641346f5a7d2607c'
		;;
	inclusive-jitter)
		harness='kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation'
		assertion='every sample maps proportionally into the inclusive equal-jitter window'
		expected_source='004eed83a91f4ab0c7c124ad7669a43a8f7790107ffe8bd8f09a4db37cebd845'
		;;
	*) printf 'Unknown retry mutation: %s\n' "$mutation" >&2; exit 2 ;;
esac
if [[ -n "$mutation" ]]; then
	actual_source=$(LC_ALL=C shasum -a 256 "$kani_dir/../../src/connection_retry.rs")
	if [[ "${actual_source%% *}" != "$expected_source" ]]; then
		printf 'Expected only the selected retry mutation in the isolated source.\n' >&2
		exit 1
	fi
fi

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

# Require the exact seven selected harnesses and all 16 cover goals.
plans=(
	kani_checks::connection_retry::permanent_and_uncertain_failures_never_redial=2
	kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation=1
	kani_checks::connection_retry::lease_and_revocation_bound_waiting_and_redial=3
	kani_checks::connection_retry::reconnect_requires_current_route_ssh_and_source_and_fences_retired_work=4
	kani_checks::connection_retry::penalty_resets_only_after_current_verified_activity_and_health=3
	kani_checks::connection_retry::clock_rollback_and_unrepresentable_wake_are_terminal=2
	kani_checks::jitter_oracle::narrow_jitter_oracle_matches_widened_formula=1
)
harnesses=()
harness_timeout=600s
if [[ -n "$mutation" ]]; then
	harness_timeout=120s
	harnesses=(--harness "$harness")
else
	for plan in "${plans[@]}"; do
		harnesses+=(--harness "${plan%=*}")
	done
fi
kani_log=$(mktemp "${EXACOPY_VERIFICATION_SCRATCH:-${TMPDIR:-/tmp}}/exacopy-endpoint-kani.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
kani_status=0
# Leave reachability and unwinding checks enabled. The outer evidence recorder
# also bounds this entire gate, including compilation and all harnesses.
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-endpoint --lib --exact \
	"${harnesses[@]}" --output-format regular -Z unstable-options \
	--harness-timeout "$harness_timeout" 2>&1 | tee "$kani_log" || kani_status=$?

if [[ "$(LC_ALL=C shasum -a 256 Cargo.lock)" != "$lock_before" ]]; then
	printf 'Cargo.lock changed during retry Kani verification.\n' >&2
	exit 1
fi
check_minisat_solver() {
	if ! awk -v selected="$*" '
		BEGIN {
			count = split(selected, names, " ")
			for (i = 1; i <= count; i++) required[names[i]] = 1
		}
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
		}
		/^Solving with / && (active in required) {
			if ($0 ~ /^Solving with MiniSAT 2[.]2[.]1 (with|without) simplifier$/) seen[active]++
			else wrong = 1
		}
		END {
			for (name in required) if (!seen[name]) wrong = 1
			exit wrong
		}
	' "$kani_log"; then
		printf 'Retry Kani requires the bundled MiniSAT 2.2.1 backend for %s.\n' "$*" >&2
		return 1
	fi
}

if [[ -n "$mutation" ]]; then
	if (( kani_status == 0 )) ||
		! grep -Fxq 'Complete - 0 successfully verified harnesses, 1 failures, 1 total.' "$kani_log" ||
		! awk -v harness="$harness" -v assertion="$assertion" '
			/^Checking harness .*\.\.\.$/ {
				seen++
				if ($0 != "Checking harness " harness "...") wrong = 1
			}
			/^Check [0-9]+:/ { unwinding = $0 ~ /[.]unwind([.][0-9]+)?$/ }
			/- Status: FAILURE$/ {
				failure_line = NR
				if (unwinding) wrong = 1
			}
			failure_line == NR - 1 && $0 ~ /- Description: "/ {
				if ($0 ~ /- Description: "unwinding assertion/) wrong = 1
				if ($0 ~ ("- Description: \"" assertion "\"$")) found++
			}
			END { exit !(seen == 1 && !wrong && found == 1) }
		' "$kani_log"; then
		printf 'Expected Kani to fail the named retry assertion for %s.\n' "$mutation" >&2
		exit 1
	fi
	if [[ "$mutation" == inclusive-jitter ]]; then
		check_minisat_solver "$harness"
	fi
	printf 'Retry mutation %s failed its expected assertion.\n' "$mutation"
	exit 0
fi
if (( kani_status != 0 )); then
	exit "$kani_status"
fi
if ! grep -Fxq "Complete - ${#plans[@]} successfully verified harnesses, 0 failures, ${#plans[@]} total." "$kani_log" ||
	! awk -v plans="${plans[*]}" '
		BEGIN {
			count = split(plans, entries, " ")
			for (entry = 1; entry <= count; entry++) {
				split(entries[entry], pair, "=")
				expected[pair[1]] = pair[2]
			}
		}
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
			if (!(active in expected)) wrong = 1
			seen[active]++
		}
		/^[[:space:]]*\*\* [0-9]+ of [0-9]+ cover properties satisfied$/ {
			cover_lines[active]++
			if (!(active in expected) || $2 != expected[active] || $4 != expected[active]) wrong = 1
		}
		END {
			for (name in expected) {
				if (seen[name] != 1 || cover_lines[name] != 1) wrong = 1
			}
			exit wrong
		}
	' "$kani_log"; then
	printf 'Retry Kani verification requires all seven selected harnesses and sixteen covered goals.\n' >&2
	exit 1
fi
check_minisat_solver \
	kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation \
	kani_checks::jitter_oracle::narrow_jitter_oracle_matches_widened_formula

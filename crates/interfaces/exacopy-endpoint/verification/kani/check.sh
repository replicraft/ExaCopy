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
		expected_source='8b7a38617b8097e5da236807b55adf43a0c399b78c0e7bc76709dd18fca5baac'
		;;
	source-fence)
		harness='kani_checks::connection_retry::reconnect_requires_current_route_ssh_and_source_and_fences_retired_work'
		assertion='every independent observation must refer to the current attempt'
		expected_source='15b83e6cbe91160dade0a5276d81732f7136032e1fba5acc29d420daf1268a68'
		;;
	health-activity)
		harness='kani_checks::connection_retry::penalty_resets_only_after_current_verified_activity_and_health'
		assertion='reset requires both qualifying activity and the full healthy duration'
		expected_source='dd9a2b5e55f99179344c52f8d6776178359cb65040f8f276c8a4e492641c4cb3'
		;;
	inclusive-jitter)
		harness='kani_checks::connection_retry::concrete_transient_backoff_is_bounded_and_claims_only_the_due_generation'
		assertion='every sample maps proportionally into the inclusive equal-jitter window'
		expected_source='34e1d63ad9732f049dcc93a4a6dff218f1a802f53006467336a4180261d46043'
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

# Require the exact nine selected harnesses and all 18 cover goals.
plans=(
	kani_checks::connection_retry::permanent_and_uncertain_failures_never_redial=2
	kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation=1
	kani_checks::connection_retry::concrete_capped_waits_reach_the_ninth_generation=1
	kani_checks::connection_retry::lease_and_revocation_bound_waiting_and_redial=3
	kani_checks::connection_retry::reconnect_requires_current_route_ssh_and_source_and_fences_retired_work=4
	kani_checks::connection_retry::penalty_resets_only_after_current_verified_activity_and_health=3
	kani_checks::connection_retry::clock_rollback_and_unrepresentable_wake_are_terminal=2
	kani_checks::jitter_oracle::narrow_jitter_oracle_matches_widened_formula=1
	kani_checks::jitter_oracle::real_equal_jitter_matches_the_exact_delay=1
)
harnesses=()
loop_contracts=()
harness_timeout=600s
if [[ -n "$mutation" ]]; then
	harness_timeout=120s
	harnesses=(--harness "$harness")
else
	loop_contracts=(-Z loop-contracts)
	for plan in "${plans[@]}"; do
		harnesses+=(--harness "${plan%=*}")
	done
fi
kani_log=$(mktemp "${EXACOPY_VERIFICATION_SCRATCH:-${TMPDIR:-/tmp}}/exacopy-endpoint-kani.XXXXXX")
trap 'rm -f "$kani_log"' EXIT
# Leave reachability and unwinding checks enabled. The outer evidence recorder
# also bounds this entire gate, including compilation and all harnesses.
set +e
CARGO_NET_OFFLINE=true "${cargo[@]}" kani --package exacopy-endpoint --lib --exact \
	"${harnesses[@]}" --output-format regular -Z unstable-options \
	-Z function-contracts -Z stubbing --no-assert-contracts "${loop_contracts[@]}" \
	--harness-timeout "$harness_timeout" 2>&1 | tee "$kani_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e
kani_status=${pipeline_status[0]}
log_status=${pipeline_status[1]}
if (( log_status != 0 )); then
	printf 'Could not retain the retry Kani log (tee exit %s, Kani exit %s).\n' \
		"$log_status" "$kani_status" >&2
	exit "$log_status"
fi

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

check_contract_stubs() {
	if ! awk -v composed="$1" '
		/^Checking harness .*\.\.\.$/ {
			active = $0
			sub(/^Checking harness /, "", active)
			sub(/\.\.\.$/, "", active)
		}
		/^  - (Verified stub|Stub): / {
			if (active == composed && composed != "" &&
			    $0 == "  - Verified stub: exacopy_endpoint::connection_retry::equal_jitter")
				verified++
			else
				wrong = 1
		}
		END { exit (wrong || verified + 0 != (composed != "")) }
	' "$kani_log"; then
		printf 'Retry Kani reported unexpected contract substitution for this gate.\n' >&2
		return 1
	fi
}

if [[ -n "$mutation" ]]; then
	if (( kani_status != 1 )); then
		printf 'Retry mutation %s requires Kani exit 1, observed %s.\n' "$mutation" "$kani_status" >&2
		exit 1
	fi
	if ! grep -Fxq 'Complete - 0 successfully verified harnesses, 1 failures, 1 total.' "$kani_log" ||
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
	check_contract_stubs ''
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
	printf 'Retry Kani verification requires all nine selected harnesses and eighteen covered goals.\n' >&2
	exit 1
fi
check_minisat_solver \
	kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation \
	kani_checks::jitter_oracle::narrow_jitter_oracle_matches_widened_formula
check_contract_stubs \
	kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation

# The aggregate success alone cannot establish that Kani used the annotated
# loop or checked its actual writes. Require the generated properties, with
# write locations bound to the three loop-carried assignments in this source.
history_file=verification/kani/connection_retry/transient_history.rs
read -r supervisor_line now_line row_line < <(awk '
	/^[[:space:]]*supervisor = next_supervisor;$/ { supervisor = NR; supervisor_count++ }
	/^[[:space:]]*now = wake_at;$/ { now = NR; now_count++ }
	/^[[:space:]]*row \+= 1;$/ { row = NR; row_count++ }
	END {
		if (supervisor_count != 1 || now_count != 1 || row_count != 1 ||
		    supervisor >= now || now >= row) exit 1
		print supervisor, now, row
	}
' "$kani_dir/../../$history_file")
if ! awk -v history=kani_checks::connection_retry::transient_backoff_is_bounded_and_claims_only_the_due_generation \
	-v source="$history_file" -v supervisor="$supervisor_line" -v now="$now_line" -v row="$row_line" '
	function at_location(line, path, start) {
		path = source ":" line
		start = index($0, path)
		return start && substr($0, start + length(path)) ~ /^(:| in function |$)/
	}
	/^Checking harness .*\.\.\.$/ {
		active = ($0 == "Checking harness " history "...")
	}
	active && /^Check [0-9]+:/ { property = $0 }
	active && /- Status: SUCCESS$/ { success = NR }
	active && success == NR - 1 && /- Description: "/ {
		description = $0
		sub(/^[[:space:]]*- Description: "/, "", description)
		sub(/"$/, "", description)
		if (property ~ /\.assigns\.[0-9]+$/ && description ~ /^Check that .* is assignable$/)
			write = NR
		if (description !~ / for loop .*check_inductive_history[^ ]*\.[0-9]+$/) next
		loop = description
		sub(/^.* for loop /, "", loop)
		if (property ~ /\.loop_invariant_base\.[0-9]+$/ &&
		    description ~ /^Check invariant before entry for loop /) entry[loop]++
		if (property ~ /\.loop_invariant_step\.[0-9]+$/ &&
		    description ~ /^Check invariant after step for loop /) step[loop]++
		if (property ~ /\.loop_decreases\.[0-9]+$/ &&
		    description ~ /^Check variant decreases after step for loop /) rank[loop]++
	}
	active && write == NR - 1 && /- Location: / {
		if (at_location(supervisor)) supervisor_checked++
		if (at_location(now)) now_checked++
		if (at_location(row)) row_checked++
	}
	END {
		for (loop in entry)
			if (step[loop] && rank[loop]) complete++
		exit !(complete == 1 && supervisor_checked && now_checked && row_checked)
	}
' "$kani_log"; then
	printf '%s\n' 'Expected checked retry loop invariant, scalar rank and all three carried writes.' >&2
	exit 1
fi

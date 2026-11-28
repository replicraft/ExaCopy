#!/usr/bin/env bash
set -euo pipefail

evidence="$RUNNER_TEMP/exacopy-evidence"
mkdir -p "$evidence"
case "$1" in
	coverage)
		report="$evidence/coverage.json"
		cargo +nightly-2026-11-04 llvm-cov nextest --locked -p exacopy-core -p exacopy-model \
			--branch --json --output-path "$report" \
			--ignore-filename-regex '(^|/)(tests|verification)/|/exacopy-core/src/component\.rs$' \
			--no-tests fail
		python3 -B -Werror .github/ci/model_coverage_test.py
		python3 -B -Werror .github/ci/model_coverage.py "$report"
		;;
	endpoint-coverage)
		report="$evidence/endpoint-coverage.json"
		summary="$evidence/endpoint-coverage-summary.json"
		minimum_line_coverage=85
		set --
		if [[ "${EXACOPY_CAPTURE_ENDPOINT_LLVM_EXPORT:-}" == 1 &&
			-z "${LLVM_COV+x}" && -z "${LLVM_PROFDATA+x}" &&
			-z "${CARGO_LLVM_COV_DENY_WARNINGS+x}" ]] &&
			sysroot=$(rustc +1.100.0 --print sysroot 2>/dev/null) &&
			[[ -x "$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov" ]] &&
			[[ -x "$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata" ]] &&
			[[ -x /usr/bin/python3 && -x "$PWD/.github/ci/endpoint_llvm_export_capture.py" ]] &&
			(umask 077; mkdir -- "$evidence/endpoint-llvm-export") 2>/dev/null; then
			set -- env \
				"LLVM_COV=$PWD/.github/ci/endpoint_llvm_export_capture.py" \
				"LLVM_PROFDATA=$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata" \
				"EXACOPY_ENDPOINT_LLVM_TOOL=$sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov" \
				"EXACOPY_ENDPOINT_LLVM_TARGET=$PWD/target/llvm-cov-target" \
				"EXACOPY_ENDPOINT_LLVM_EVIDENCE=$evidence/endpoint-llvm-export"
		fi
		ordinary_report="$report"
		witness_prepared=0
		witness_blocked=0
		if [[ "${EXACOPY_MEASURE_ORDINARY_WITNESS:-}" == 1 ]]; then
			witness=crates/platform/exacopy-platform/verification/witnessed_components_ext4/ordinary_coverage.py
			if (( $# > 0 )) && python3 -B -Werror "$witness" prepare; then
				witness_prepared=1
				ordinary_report="$evidence/endpoint-coverage-ordinary.json"
			else
				witness_blocked=1
			fi
		fi
		owner_packages=(-p exacopy-core -p exacopy-endpoint -p exacopy-platform)
		if (( witness_prepared )); then
			owner_report="$evidence/endpoint-coverage-owner-only.json"
			witness_evidence="$evidence/endpoint-ordinary-witness"
			owner_junit=target/nextest/ci-endpoint-coverage-owner/junit.xml
			junit=target/nextest/ci-endpoint-coverage/junit.xml
			[[ ! -e "$owner_junit" && ! -L "$owner_junit" ]]
			cargo +1.100.0 llvm-cov nextest --locked "${owner_packages[@]}" \
				--profile ci-endpoint-coverage-owner \
				--json --show-missing-lines --output-path "$owner_report" --no-tests fail
			# Compile the known default owner test targets and one CLI integration target.
			# JUnit parity independently detects omission from the owner-only campaign.
			coverage_tests=(
				--lib --test component --test identity
				--test connection_retry --test contracts --test io_diagnostics
				--test linux_remote_qualification --test ssh_sftp
				--test linux_job_capabilities --test linux_plan_bundle --test linux_scope
				--test linux_source --test linux_stage --test linux_sync_history_ext4
				--test linux_sync_history_members --test protected_snapshot_diagnostics
				--test source_observation --test job_bootstrap
			)
			# Keep old coverage objects and counters out of the expanded default graph.
			if ! { (umask 077; set -o noclobber
					cat "$owner_junit" > "$witness_evidence/owner-nextest.xml") &&
				[[ ! -e "$junit" && ! -L "$junit" ]] &&
				cargo +1.100.0 llvm-cov clean &&
				"$@" cargo +1.100.0 llvm-cov nextest --locked "${owner_packages[@]}" \
					-p exacopy-cli --exclude-from-report exacopy-cli --profile ci-endpoint-coverage \
					"${coverage_tests[@]}" \
					-E 'package(=exacopy-core) | package(=exacopy-endpoint) | package(=exacopy-platform) | binary_id(=exacopy-cli::job_bootstrap)' \
					--json --show-missing-lines --output-path "$ordinary_report" --no-tests fail &&
				(umask 077; set -o noclobber
					cat "$junit" > "$witness_evidence/ordinary-nextest.xml" &&
					printf '0\n' > "$witness_evidence/ordinary-producer.exit") &&
				python3 -B -Werror "$witness" combine &&
				ln -T -- "$witness_evidence/combined-llvm.json" "$report"; }; then
				report="$owner_report"
				witness_blocked=1
			fi
		else
			"$@" cargo +1.100.0 llvm-cov nextest --locked "${owner_packages[@]}" \
				--json --show-missing-lines --output-path "$ordinary_report" --no-tests fail
		fi
		if (( witness_blocked )); then
			printf 'Ordinary witness coverage blocked. Evaluating ordinary coverage.\n' >&2
		fi
		jq '
			def source_lines($path):
				[.data[0].files[] |
					select(.filename | test("(^|/)crates/" + $path)) |
					.summary.lines] |
				{count: (map(.count) | add // 0), covered: (map(.covered) | add // 0)};
			if (.data | length) != 1 then error("expected one coverage data set") else
				{"exacopy-core": source_lines("foundation/exacopy-core/src/component\\.rs$"),
				 "exacopy-endpoint": source_lines("interfaces/exacopy-endpoint/src/"),
				 "exacopy-platform": source_lines("platform/exacopy-platform/src/")}
			end
		' "$report" > "$summary"
		cat "$summary"
		jq -e --argjson minimum "$minimum_line_coverage" '
			all(.[]; .count > 0 and .covered * 100 >= .count * $minimum)
		' "$summary"
		if (( witness_blocked )); then exit 1; fi
		;;
	mutation)
		# cargo-mutants 27.1.0 leaves [workspace.dependencies] paths relative
		# in its scratch copy. CI passes --in-place in a disposable checkout.
		cargo +1.100.0 mutants "${@:2}" --package exacopy-core --package exacopy-model \
			--test-package exacopy-core --test-package exacopy-model --output "$evidence" --no-shuffle \
			--file crates/foundation/exacopy-core/src/identity.rs \
			--file crates/foundation/exacopy-model/src/range.rs \
			--file crates/foundation/exacopy-model/src/transaction.rs -- --locked
		report="$evidence/mutants.out/outcomes.json"
		jq '{total_mutants, caught, missed, timeout, unviable}' "$report"
		jq -e '
			.caught > 0 and .missed == 0 and .timeout == 0 and
			.total_mutants == .caught + .unviable and
			(.outcomes[0] | .scenario == "Baseline" and .summary == "Success") and
			([.outcomes[1:][].scenario.Mutant.file] | unique == [
				"crates/foundation/exacopy-core/src/identity.rs",
				"crates/foundation/exacopy-model/src/range.rs",
				"crates/foundation/exacopy-model/src/transaction.rs"
			])
		' "$report"
		;;
	*)
		printf 'Usage: assurance.sh coverage|endpoint-coverage|mutation\n' >&2
		exit 2
		;;
esac

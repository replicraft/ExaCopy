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
		"$@" cargo +1.100.0 llvm-cov nextest --locked -p exacopy-core -p exacopy-endpoint -p exacopy-platform \
			--json --show-missing-lines --output-path "$ordinary_report" --no-tests fail
		if (( witness_prepared )); then
			witness_evidence="$evidence/endpoint-ordinary-witness"
			if ! { (umask 077; set -o noclobber; printf '0\n' > "$witness_evidence/ordinary-producer.exit") &&
				python3 -B -Werror "$witness" combine &&
				ln -T -- "$witness_evidence/combined-llvm.json" "$report"; }; then
				report="$ordinary_report"
				witness_blocked=1
			fi
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

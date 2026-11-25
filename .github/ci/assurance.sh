#!/usr/bin/env bash
set -euo pipefail

evidence="$RUNNER_TEMP/exacopy-evidence"
mkdir -p "$evidence"
case "$1" in
	coverage)
		report="$evidence/coverage.json"
		cargo +nightly-2026-11-04 llvm-cov nextest --locked -p exacopy-model \
			--branch --json --summary-only --output-path "$report" \
			--ignore-filename-regex '(^|/)(tests|verification)/' --no-tests fail
		jq '.data[0].totals | {lines, branches}' "$report"
		jq -e '
			(.data | length == 1) and
			([.data[0].files[].filename | split("/") | last] | sort ==
				["identity.rs", "range.rs", "transaction.rs"]) and
			(.data[0].totals |
				.lines.count > 0 and .lines.covered * 100 >= .lines.count * 95 and
				.branches.count > 0 and .branches.covered * 100 >= .branches.count * 90)
		' "$report"
		;;
	endpoint-coverage)
		report="$evidence/endpoint-coverage.json"
		summary="$evidence/endpoint-coverage-summary.json"
		minimum_line_coverage=85
		cargo +1.100.0 llvm-cov nextest --locked -p exacopy-endpoint -p exacopy-platform \
			--json --show-missing-lines --output-path "$report" --no-tests fail
		jq '
			def source_lines($crate):
				[.data[0].files[] |
					select(.filename | test("(^|/)crates/endpoints/" + $crate + "/src/")) |
					.summary.lines] |
				{count: (map(.count) | add // 0), covered: (map(.covered) | add // 0)};
			if (.data | length) != 1 then error("expected one coverage data set") else
				{"exacopy-endpoint": source_lines("endpoint"), "exacopy-platform": source_lines("platform")}
			end
		' "$report" > "$summary"
		cat "$summary"
		jq -e --argjson minimum "$minimum_line_coverage" '
			all(.[]; .count > 0 and .covered * 100 >= .count * $minimum)
		' "$summary"
		;;
	mutation)
		cargo +1.100.0 mutants --package exacopy-model --output "$evidence" --no-shuffle \
			--file crates/core/model/src/identity.rs \
			--file crates/core/model/src/range.rs \
			--file crates/core/model/src/transaction.rs -- --locked
		report="$evidence/mutants.out/outcomes.json"
		jq '{total_mutants, caught, missed, timeout, unviable}' "$report"
		jq -e '
			.caught > 0 and .missed == 0 and .timeout == 0 and
			.total_mutants == .caught + .unviable and
			(.outcomes[0] | .scenario == "Baseline" and .summary == "Success") and
			([.outcomes[1:][].scenario.Mutant.file] | unique == [
				"crates/core/model/src/identity.rs",
				"crates/core/model/src/range.rs",
				"crates/core/model/src/transaction.rs"
			])
		' "$report"
		;;
	*)
		printf 'Usage: assurance.sh coverage|endpoint-coverage|mutation\n' >&2
		exit 2
		;;
esac

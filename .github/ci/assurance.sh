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
		cargo +1.100.0 llvm-cov nextest --locked -p exacopy-core -p exacopy-endpoint -p exacopy-platform \
			--json --show-missing-lines --output-path "$report" --no-tests fail
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

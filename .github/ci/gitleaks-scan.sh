#!/usr/bin/env bash
set -uo pipefail
set +e

# Only the four-field template reaches the metadata validator.
gitleaks git --redact=100 --no-banner --gitleaks-ignore-path .github/gitleaksignore \
	--report-format template --report-template .github/ci/gitleaks-metadata.tmpl --report-path=- . 2>/dev/null |
	python3 -B .github/ci/gitleaks_metadata.py
status=("${PIPESTATUS[@]}")
if (( status[0] != 0 )); then
	printf 'Gitleaks exit status: %s\n' "${status[0]}" >&2
	exit "${status[0]}"
fi
exit "${status[1]}"

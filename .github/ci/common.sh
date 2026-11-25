#!/usr/bin/env bash

hash_stream() {
	if command -v sha256sum >/dev/null; then
		sha256sum
	else
		shasum -a 256
	fi | cut -d ' ' -f 1
}

fetch() {
	local url=$1 expected=$2 output=$3 actual
	curl --fail --silent --show-error --location --proto '=https' --retry 3 \
		--connect-timeout 20 --max-time 240 --output "$output" "$url"
	actual=$(hash_stream < "$output")
	if [[ "$actual" != "$expected" ]]; then
		printf 'SHA-256 mismatch for %s: expected %s, got %s\n' "$url" "$expected" "$actual" >&2
		return 1
	fi
	printf 'Verified %s  %s\n' "$actual" "$url"
}

add_path() {
	local path=$1
	if [[ ${RUNNER_OS:-} == Windows ]]; then
		path=$(cygpath -m "$path")
	fi
	printf '%s\n' "$path" >> "$GITHUB_PATH"
}

runner_temp() {
	if [[ ${RUNNER_OS:-} == Windows ]]; then
		cygpath -u "$RUNNER_TEMP"
	else
		printf '%s\n' "$RUNNER_TEMP"
	fi
}

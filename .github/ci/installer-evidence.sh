#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=.github/ci/common.sh
source "$(dirname "$0")/common.sh"

require_clean_source() {
	if [[ -n "$(git status --porcelain)" ]]; then
		printf 'Installer evidence requires a clean source checkout.\n' >&2
		return 1
	fi
}

target_dir="$(runner_temp)/exacopy-installer-target"
case "$1" in
	environment)
		if [[ "$(git rev-parse HEAD)" != "$GITHUB_SHA" ]]; then
			printf 'Installer checkout differs from the workflow revision.\n' >&2
			exit 1
		fi
		require_clean_source
		if [[ -e "$target_dir" || -L "$target_dir" ]]; then
			printf 'Installer artifact target must be absent before building.\n' >&2
			exit 1
		fi
		printf 'artifact_scope=ephemeral-test-fixture\n'
		case "$RUNNER_OS" in
			Linux)
				python3 -VV
				openssl version
				/usr/bin/openssl version
				getconf GNU_LIBC_VERSION
				;;
			macOS)
				python3 -VV
				openssl version
				/usr/bin/openssl version
				sw_vers
				;;
			Windows)
				python -VV
				pwsh -Version
				pwsh -NoLogo -NoProfile -NonInteractive \
					-Command '[System.Environment]::OSVersion.Version; [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription'
				;;
			*)
				printf 'Unsupported installer fixture runner: %s\n' "$RUNNER_OS" >&2
				exit 1
				;;
		esac
		;;
	artifact)
		require_clean_source
		executable=exacopy
		if [[ "$RUNNER_OS" == Windows ]]; then executable=exacopy.exe; fi
		artifact="$target_dir/release/$executable"
		test -f "$artifact"
		test ! -L "$artifact"
		test -s "$artifact"
		bytes=$(wc -c < "$artifact")
		digest=$(hash_stream < "$artifact")
		printf 'artifact=%s\ntarget=%s\nbytes=%d\nsha256=%s\n' \
			"$executable" "$EXPECTED_RUST_HOST" "$bytes" "$digest"
		;;
	*)
		printf 'Unknown installer evidence phase: %s\n' "$1" >&2
		exit 1
		;;
esac

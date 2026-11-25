#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=.github/ci/common.sh
source "$(dirname "$0")/common.sh"

gate=$1
shift
temp_dir=$(runner_temp)
evidence="$temp_dir/exacopy-evidence"
mkdir -p "$evidence"
log="$evidence/$gate.log"
metadata="$evidence/$gate.txt"
commit=$(git rev-parse HEAD)
tree=$(git rev-parse 'HEAD^{tree}')
working_tree=$(git status --porcelain)
lockfile_hash=$(hash_stream < Cargo.lock)
dirty=false
if [[ -n "$working_tree" ]]; then
	dirty=true
fi

# Keep these values alongside the raw output, including when the command fails.
{
	printf 'repository=%s\n' "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"
	printf 'commit=%s\n' "$commit"
	printf 'git_tree=%s\n' "$tree"
	printf 'dirty=%s\n' "$dirty"
	printf 'lockfile_sha256=%s\n' "$lockfile_hash"
	printf 'runner=%s %s %s\n' "$RUNNER_OS" "$RUNNER_ARCH" "${ImageVersion:-unknown}"
	printf 'kernel=%s\n' "$(uname -srm)"
	printf 'run=%s attempt=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
	printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'command='
	printf ' %q' "$@"
	printf '\n'
} > "$metadata"

start=$SECONDS
set +e
"$@" 2>&1 | tee "$log"
pipeline=("${PIPESTATUS[@]}")
set -e
log_hash=$(hash_stream < "$log")
{
	printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'duration_seconds=%s\n' "$((SECONDS - start))"
	printf 'exit_status=%s\n' "${pipeline[0]}"
	printf 'log_sha256=%s\n' "$log_hash"
} >> "$metadata"

if (( pipeline[1] != 0 )); then
	printf 'Could not retain output for %s\n' "$gate" >&2
	exit "${pipeline[1]}"
fi
exit "${pipeline[0]}"

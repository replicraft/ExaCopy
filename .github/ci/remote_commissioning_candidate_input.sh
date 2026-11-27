#!/usr/bin/env bash
set -euo pipefail

case "$GITHUB_JOB" in
	preview-direct) fixture=exacopy-direct-commissioning ;;
	embedded) fixture=exacopy-wireguard-commissioning ;;
	*) exit 2 ;;
esac

[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ && "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || exit 1
input="$RUNNER_TEMP/exacopy-preview-candidate-input"
marker="$RUNNER_TEMP/exacopy-preview-candidate-input.pending"
report="$RUNNER_TEMP/exacopy-preview-candidate-cleanup.txt"
owner="$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT/$GITHUB_JOB"
uid=$(id -u)

stage() {
	# An empty artifact ID would tell download-artifact to select every artifact.
	[[ "$ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]] || return 1
	test "$CANDIDATE_RUN_ATTEMPT" = "$GITHUB_RUN_ATTEMPT"
	test ! -e "$marker"
	test ! -L "$marker"
	mkdir -m 700 -- "$input"
	identity=$(stat -c '%d:%i:%u:%a' -- "$input")
	[[ "$identity" == *:"$uid":700 ]] || return 1
	(
		umask 077
		set -o noclobber
		printf '%s\n%s\n' "$owner" "$identity" > "$marker"
	)
}

retain_uncertainty() {
	(
		umask 077
		set -o noclobber
		printf 'status=blocked\nreason=%s\nrun=%s\n' "$1" "$owner" > "$report"
	)
	exit 1
}

cleanup() {
	if [[ ! -e "$marker" && ! -L "$marker" && ! -e "$input" && ! -L "$input" ]]; then
		return
	fi
	local uncertainty="$RUNNER_TEMP/$fixture/report/cleanup-unconfirmed.json"
	if [[ -e "$uncertainty" || -L "$uncertainty" ]]; then
		retain_uncertainty "fixture-cleanup-unconfirmed"
	fi
	if [[ ! -d "$input" || -L "$input" || ! -f "$marker" || -L "$marker" ]]; then
		retain_uncertainty "input-identity-unavailable"
	fi
	local identity marker_identity
	identity=$(stat -c '%d:%i:%u:%a' -- "$input") || retain_uncertainty "input-stat-failed"
	marker_identity=$(stat -c '%u:%a:%h:%s' -- "$marker") || retain_uncertainty "marker-stat-failed"
	if [[ "$identity" != *:"$uid":700 || "$marker_identity" != "$uid:600:1:"* ]]; then
		retain_uncertainty "input-or-marker-custody-changed"
	fi
	if ! cmp -s -- "$marker" <(printf '%s\n%s\n' "$owner" "$identity"); then
		retain_uncertainty "input-identity-changed"
	fi
	rm -r --one-file-system -- "$input" || retain_uncertainty "input-removal-failed"
	if [[ -e "$input" || -L "$input" ]]; then
		retain_uncertainty "input-absence-unconfirmed"
	fi
	rm -- "$marker" || retain_uncertainty "marker-removal-failed"
}

case "${1:-}" in
	stage) stage ;;
	cleanup) cleanup ;;
	*) exit 2 ;;
esac

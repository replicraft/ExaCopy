#!/usr/bin/env bash
set -euo pipefail

# Both direct commissioning workflows use the same independent Ubuntu package.
tool_dir="$RUNNER_TEMP/exacopy-commissioning-tools"
tool_marker="$RUNNER_TEMP/exacopy-evidence/direct-digest-tool.pending"

stage() {
	(
	  set -o noclobber
	  printf '%s/%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" > "$tool_marker"
	)
	mkdir -m 700 "$tool_dir"
	tool_identity=$(stat -c '%d:%i:%u:%a' -- "$tool_dir")
	[[ "$tool_identity" == *:"$(id -u)":700 ]]
	printf '%s/%s\n%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$tool_identity" > "$tool_dir/fixture-owner"
	cd "$tool_dir"
	mkdir -- unpacked
	apt-get -o APT::Get::AllowUnauthenticated=false download b3sum
	packages=(b3sum_*_amd64.deb)
	test "${#packages[@]}" -eq 1
	test "$(dpkg-deb --field "${packages[0]}" Package)" = b3sum
	test "$(dpkg-deb --field "${packages[0]}" Architecture)" = amd64
	dpkg-deb --extract "${packages[0]}" unpacked
	test "$(stat -c '%d:%i:%u:%a' -- "$tool_dir")" = "$tool_identity"
	test -x "$tool_dir/unpacked/usr/bin/b3sum"
	printf '%s\n' "$tool_dir/unpacked/usr/bin" >> "$GITHUB_PATH"
}

cleanup() {
	case "$COMMISSIONING_CAMPAIGN" in
	  direct|retry) ;;
	  *) exit 1 ;;
	esac
	uncertainty="$RUNNER_TEMP/exacopy-${COMMISSIONING_CAMPAIGN}-commissioning/report/cleanup-unconfirmed.json"
	if [[ -e "$uncertainty" || -L "$uncertainty" ]]; then
	  exit 0
	fi
	if [[ ! -e "$tool_marker" && ! -L "$tool_marker" ]]; then
	  test ! -e "$tool_dir"
	  test ! -L "$tool_dir"
	  exit 0
	fi
	test -f "$tool_marker"
	test ! -L "$tool_marker"
	test "$(cat -- "$tool_marker")" = "$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT"
	if [[ -e "$tool_dir" || -L "$tool_dir" ]]; then
	  if [[ ! -d "$tool_dir" || -L "$tool_dir" ]]; then
	    echo "Digest-tool cleanup blocked because the owned directory has another type." >&2
	    exit 1
	  fi
	  tool_identity=$(stat -c '%d:%i:%u:%a' -- "$tool_dir")
	  if [[ "$tool_identity" != *:"$(id -u)":700 ]]; then
	    echo "Digest-tool cleanup blocked because the directory owner or mode changed ($tool_identity)." >&2
	    exit 1
	  fi
	  if [[ ! -f "$tool_dir/fixture-owner" || -L "$tool_dir/fixture-owner" ]]; then
	    echo "Digest-tool cleanup blocked because the directory identity record is unavailable." >&2
	    exit 1
	  fi
	  expected_owner="$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT"$'\n'"$tool_identity"
	  if [[ "$(cat -- "$tool_dir/fixture-owner")" != "$expected_owner" ]]; then
	    echo "Digest-tool cleanup blocked because the recorded ownership differs." >&2
	    exit 1
	  fi
	  rm -r --one-file-system -- "$tool_dir"
	  test ! -e "$tool_dir"
	  test ! -L "$tool_dir"
	fi
	rm -- "$tool_marker"
}

case "${1:-}" in
	stage) stage ;;
	cleanup) cleanup ;;
	*) exit 2 ;;
esac

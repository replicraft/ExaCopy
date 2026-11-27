#!/usr/bin/env bash
set -euo pipefail

case "${1-}" in
	ordinary)
		fixture=strict_native_copy_publishes_the_stage_and_commits_its_receipt
		;;
	timestamp-eligible)
		fixture=strict_native_copy_with_timestamp_eligible_source_commits_its_receipt
		;;
	*)
		printf 'Select the ordinary or timestamp-eligible synthetic source profile.\n' >&2
		exit 2
		;;
esac

printf 'synthetic_source_profile=%s\n' "$1"
if [[ "$(uname -s)" != Darwin || "$(id -u)" == 0 ]]; then
	printf 'qualification=blocked reason=requires-unprivileged-native-macos\n' >&2
	exit 1
fi

umask 077
sw_vers
fixture_volume=$(df -P /private/tmp)
printf '%s\n' "$fixture_volume"
fixture_device=$(awk 'NR == 2 { print $1 }' <<< "$fixture_volume")
mount | awk -v device="$fixture_device" '$1 == device'
test_name="assembly::macos::job::tests::publication::$fixture"
exec cargo +1.100.0 nextest run --locked -p exacopy-cli --lib \
	--no-default-features --features experimental-apfs-copy \
	--profile ci-experimental-apfs-copy --no-tests fail --run-ignored only \
	--success-output final -E "test(=$test_name)"

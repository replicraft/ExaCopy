#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$verification_dir/../../../.." && pwd -P)

case ${1:-rust} in
	rust)
		cd "$repo"
		exec cargo nextest run --locked -p exacopy-manifest --profile ci --no-tests fail
		;;
	*)
		printf '%s\n' 'usage: check.sh [rust]' >&2
		exit 2
		;;
esac

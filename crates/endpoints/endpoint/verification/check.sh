#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
case ${1:-kani} in
	kani) exec "$verification_dir/kani/check.sh" ;;
	*)
		printf '%s\n' 'usage: check.sh [kani]' >&2
		exit 2
		;;
esac

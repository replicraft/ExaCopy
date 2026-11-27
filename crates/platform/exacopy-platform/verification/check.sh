#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)

case ${1:-all} in
	tlc | all) exec python3 -B "$verification_dir/tla/check-publication-build-retirement.py" ;;
	*)
		printf '%s\n' 'usage: check.sh [tlc|all]' >&2
		exit 2
		;;
esac

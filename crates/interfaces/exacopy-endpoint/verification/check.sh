#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
case ${1:-kani} in
	kani) [ "$#" -le 1 ] || exit 2; exec "$verification_dir/kani/check.sh" ;;
	mutation) [ "$#" -eq 2 ] && [ -n "$2" ] || exit 2; exec "$verification_dir/kani/check.sh" "$2" ;;
	*) printf '%s\n' 'usage: check.sh [kani | mutation ID]' >&2; exit 2 ;;
esac

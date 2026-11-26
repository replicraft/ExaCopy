#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$verification_dir/../../../.." && pwd -P)

check_miri() (
	cd "$repo"
	# The native suite runs the generated properties, which read their regression corpus.
	rustup run nightly-2026-11-04 cargo miri test --locked -p exacopy-core -p exacopy-model --tests -- \
		--skip checked_ranges_agree_with_wide_integer_arithmetic \
		--skip generated_copy_histories_agree_with_the_reference_ledger
)

case ${1:-all} in
	lean) exec "$verification_dir/lean-check.sh" ;;
	kani) exec "$verification_dir/kani/check.sh" ;;
	tlc)
		"$verification_dir/tla/check.sh"
		python3 -B "$verification_dir/tla/check-sync.py"
		python3 -B "$verification_dir/tla/check-continuation.py"
		exec python3 -B "$verification_dir/tla/check-witness-namespace.py"
		;;
	miri) check_miri ;;
	all)
		status=0
		for gate in lean kani tlc miri; do
			"$verification_dir/check.sh" "$gate" || status=1
		done
		exit "$status"
		;;
	*)
		printf '%s\n' 'usage: check.sh [lean|kani|tlc|miri|all]' >&2
		exit 2
		;;
esac

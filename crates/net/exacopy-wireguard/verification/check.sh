#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$verification_dir/../../../.." && pwd -P)

case ${1:-rust} in
	rust)
		cd "$repo"
		exec cargo nextest run --locked -p exacopy-wireguard \
			--no-default-features --features experimental-protocol --no-tests fail \
			-- --exact protocol::tests::rekey::one_bound_peer_pair_exchanges_payload_after_original_lifetime
		;;
	*)
		printf '%s\n' 'usage: check.sh [rust]' >&2
		exit 2
		;;
esac

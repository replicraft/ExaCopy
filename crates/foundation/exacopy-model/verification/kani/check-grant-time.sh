#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != 1 || "$1" != kani ]]; then
	printf 'usage: check-grant-time.sh kani\n' >&2
	exit 2
fi
kani_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$kani_dir/check.sh" --grant-time

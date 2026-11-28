#!/bin/sh
set -eu
verification_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$verification_dir/../../.." && pwd -P)
case ${1:-rust} in
    rust)
        cd "$repo"
        exec cargo nextest run --locked -p exacopy-cli --profile ci --no-tests fail
        ;;
    kani)
        shift
        exec "$verification_dir/kani/check.sh" "$@"
        ;;
    *)
        printf '%s\n' 'usage: check.sh [rust|kani]' >&2
        exit 2
        ;;
esac

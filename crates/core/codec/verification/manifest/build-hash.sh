#!/bin/bash
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd -P)
source_dir="${1:?path to BLAKE3 C source directory}"
cc -std=c11 -O2 -DBLAKE3_USE_NEON=0 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 \
    -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -I "$source_dir" \
    "$dir/hash.c" "$source_dir/blake3.c" "$source_dir/blake3_portable.c" \
    "$source_dir/blake3_dispatch.c" -o "$dir/hash"

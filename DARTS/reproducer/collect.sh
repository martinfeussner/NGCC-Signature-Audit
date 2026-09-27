#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
signatures=${1:-17000000}
key_id=${2:-0}
workers=${3:-4}
output=${4:-"$here/build/collection"}

case "$signatures:$key_id:$workers" in
    *[!0-9:]*) echo "usage: $0 [signatures] [key-id] [workers] [output-dir]" >&2; exit 2 ;;
esac

"$here/build.sh"
mkdir -p "$output"
OMP_NUM_THREADS="$workers" "$here/build/darts_collect" \
    "$signatures" "$key_id" "$output/scores.bin" \
    "$output/state.bin" 10000
"$here/build/darts_dump_public_matrix" "$output/scores.bin" \
    > "$output/public-matrix.txt"

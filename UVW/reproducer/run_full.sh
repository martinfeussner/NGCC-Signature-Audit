#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
signatures=${1:-300}
workers=${2:-4}
seed_count=${UVW_SEED_COUNT:-1600}

case "$signatures:$workers:$seed_count" in
    *[!0-9:]*) echo "usage: $0 [signatures] [workers]" >&2; exit 2 ;;
esac
if [ "$signatures" -lt 1 ] || [ "$workers" -lt 1 ] || [ "$workers" -gt 32 ]; then
    echo "usage: $0 [signatures] [workers:1..32]" >&2
    exit 2
fi

build=$("$here/build.sh")
run="$here/build/run-$signatures"
mkdir -p "$run"
prefix="$run/uvw"

"$build/uvw_collect" "$signatures" "$prefix" "$workers"
env OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-4}" \
    "$python" "$here/uvw_pair_likelihood.py" \
    "$prefix.errors.bin" --out "$prefix.candidates.tsv"
"$build/uvw_public_forgery" \
    "$prefix.pk.bin" "$prefix.candidates.tsv" "$seed_count" \
    "$prefix.api-signature.bin"

wc -c "$prefix.api-signature.bin"
sha256sum "$prefix.pk.bin" "$prefix.errors.bin" \
    "$prefix.candidates.tsv" "$prefix.api-signature.bin"

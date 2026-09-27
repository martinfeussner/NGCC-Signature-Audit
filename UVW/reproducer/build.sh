#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")
submission="$harness/sign-32/Implementations/Reference_Implementation/UVW-128"
build="$here/build"

if [ ! -f "$submission/SIG_AlgorithmInstance.c" ]; then
    echo "pinned UVW-128 submission source is missing" >&2
    exit 1
fi

mkdir -p "$build"
scratch=$(mktemp -d "$build/source.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
cp -R "$submission/." "$scratch/"

# Add only the adapter that keeps the generated key in memory for the local
# signing oracle.  The public recovery binaries receive no secret input.
cat "$here/uvw_reproducer_keygen.inc" >> "$scratch/SIG_AlgorithmInstance.c"

# The archive contains verbose DBG_SIGN/DBG_VFY prints.  Remove those prints
# and their print-only counters from the temporary build copy.
sed \
    -e '/size_t fe_hw = vf3_hamming_weight(fe);/d' \
    -e '/size_t d_zero = 0;/d' \
    -e '/size_t p_dup = 0;/d' \
    -e '/d_zero++/d' \
    -e '/p_dup++/d' \
    -e '/fprintf(stderr, "DBG_/d' \
    "$scratch/uvw.c" > "$scratch/uvw.c.clean"
mv "$scratch/uvw.c.clean" "$scratch/uvw.c"

cc=${CC:-cc}
cflags=${CFLAGS:--O3 -std=gnu11 -Wall -Wextra}
includes="-I$scratch -I$scratch/fq_arithmetic"
common="$scratch/uvw.c $scratch/gauss.c $scratch/auxfunc.c $scratch/drng.c \
$scratch/fq_arithmetic/vf3.c $scratch/fq_arithmetic/mf3.c \
$scratch/fq_arithmetic/dp.c"

# shellcheck disable=SC2086
$cc $cflags -DUSE_API_PKC $includes \
    "$here/uvw_collect.c" "$scratch/SIG_AlgorithmInstance.c" $common \
    -lm -o "$build/uvw_collect"

# shellcheck disable=SC2086
$cc $cflags -DUSE_API_PKC $includes \
    "$here/uvw_public_forgery.c" $common \
    -lm -o "$build/uvw_public_forgery"

printf '%s\n' "$build"

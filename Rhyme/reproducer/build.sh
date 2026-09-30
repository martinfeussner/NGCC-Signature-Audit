#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
reference="$here/reference/Rhyme-SHAKE-128"
build="$here/build"
cc=${CC:-gcc}
cflags=${CFLAGS:--O3 -std=c99 -Wall -Wextra}

(cd "$here" && sha256sum --check SOURCE_SHA256SUMS >/dev/null)

rm -rf "$build"
mkdir -p "$build/src" "$build/bin"

prepare() {
    name=$1
    shift
    destination="$build/src/$name"
    mkdir -p "$destination"
    cp -R "$reference/." "$destination/"
    for patch_name in "$@"; do
        patch -s -d "$destination" -p1 < "$here/patches/$patch_name"
    done
}

prepare pristine
prepare independent attack-common.patch restart-counters.patch
prepare reuse attack-common.patch reuse-tape.patch restart-counters.patch
prepare safe attack-common.patch safe-m.patch restart-counters.patch
prepare ungated attack-common.patch ungated-codec.patch

compile() {
    source_tree=$1
    harness=$2
    output=$3
    (
        cd "$source_tree"
        # shellcheck disable=SC2086
        "$cc" $cflags -I. -Iinclude -Isrc/keygen \
            -DRHYME_NO_AES -DRHYME_MODE=128 \
            -DOUTPUT_BLANK_TEST_VECTORS=0 \
            '-DALGORITHM_INSTANCE="Rhyme-SHAKE-128"' \
            -o "$output" "$harness" \
            src/poly.c src/ntt.c src/ntt_tables.c src/sampler.c \
            src/encoding.c src/packing.c src/sign.c src/zpntt.c \
            src/symmetric-shake.c src/fips202.c rhyme_xof.c \
            src/keygen/kg_main.c src/keygen/kg_solver.c \
            src/keygen/kg_zint.c src/keygen/kg_ntt.c \
            src/keygen/kg_primes.c randombytes.c drng.c -lm
    )
}

compile "$build/src/pristine" "$here/review_forge.c" \
    "$build/bin/pristine_forge"
compile "$build/src/pristine" "$here/pristine_validate_oracle.c" \
    "$build/bin/pristine_validate_oracle"
compile "$build/src/independent" "$here/review_collect_oracle_count.c" \
    "$build/bin/independent_collect"
compile "$build/src/reuse" "$here/review_collect_oracle_count.c" \
    "$build/bin/reuse_collect"
compile "$build/src/safe" "$here/review_collect_oracle_count.c" \
    "$build/bin/safe_collect"
compile "$build/src/ungated" "$here/review_collect.c" \
    "$build/bin/ungated_collect"

printf '%s\n' "$build"

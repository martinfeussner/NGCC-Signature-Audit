#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
reference="$here/reference/CS-128"
attack="$here/attack"
build="$here/build"
cc=${CC:-gcc}
cflags=${CFLAGS:--O3 -flto -fcommon -std=gnu11}

check_hash() {
    expected=$1
    path=$2
    actual=$(sha256sum "$path" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        printf 'source hash mismatch: %s\nexpected: %s\nactual:   %s\n' \
            "$path" "$expected" "$actual" >&2
        exit 1
    fi
}

# These are the byte hashes of the bundled CRLF copies of the submitted source.
# Git is told not to normalize this directory in the repository's
# .gitattributes file.  Their LF-normalized hashes match the official archive.
check_hash ab3111fb2550063400b3541e47bfe8629cbdeaa9de825ef433178e9050353492 \
    "$reference/cs.c"
check_hash 989663e06f4872c4bc8b8d1b873c0250037c2eac74cb31964ac9bd791f7c24f3 \
    "$reference/sampling.c"

mkdir -p "$build"
sources="
$attack/leak_reference.c
$reference/auxfunc.c
$reference/bits-hints.c
$reference/conversion.c
$reference/cs.c
$reference/drng.c
$reference/encodings.c
$attack/ntt.c
$reference/sampling.c
"

# shellcheck disable=SC2086
$cc $cflags -w -I"$reference" -I"$attack" $sources -lm \
    -o "$build/cs128_reference_baseline"
# shellcheck disable=SC2086
$cc $cflags -w -DREFERENCE_REFINEMENT -I"$reference" -I"$attack" $sources -lm \
    -o "$build/cs128_reference_refinement"
# shellcheck disable=SC2086
$cc $cflags -w -DREFERENCE_REFINEMENT -DPOISON_DIAGNOSTIC_TRUTH \
    -I"$reference" -I"$attack" $sources -lm \
    -o "$build/cs128_reference_refinement_poison_control"

printf '%s\n' "$build"

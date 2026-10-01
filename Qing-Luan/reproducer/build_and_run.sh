#!/usr/bin/env bash
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cc=${CC:-gcc}

core_sources="fq_arith.c hash.c restr.c rsdp.c mpc.c keygen.c sign.c verify.c"

compile_api() {
    semantics=$1
    aligned=$2
    profile=$3
    base="$here/$semantics/QingLuan-$profile"
    sources=""
    for source in $core_sources; do
        sources="$sources $base/src/$source"
    done
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O2 -Wall -Wextra -Wpedantic \
        -DSPEC_ALIGNED="$aligned" -DUSE_API_DRNG=1 \
        -I"$base/include" -I"$base/api_pkc" $sources \
        "$base/api_pkc/drng.c" "$base/api_pkc/utils_adapter.c" \
        "$here/hostile_review.c" -o "$base/hostile_review_api"
}

compile_standalone() {
    profile=$1
    base="$here/spec-aligned/QingLuan-$profile"
    sources=""
    for source in $core_sources; do
        sources="$sources $base/src/$source"
    done
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O2 -Wall -Wextra -Wpedantic \
        -DSPEC_ALIGNED=1 -DUSE_API_DRNG=0 \
        -I"$base/include" $sources "$base/src/utils.c" \
        "$here/hostile_review.c" -o "$base/hostile_review_standalone"
}

compile_combined() {
    semantics=$1
    aligned=$2
    profile=$3
    base="$here/$semantics/QingLuan-$profile"
    sources=""
    for source in $core_sources; do
        sources="$sources $base/src/$source"
    done
    # The combined public extractor uses the local submission-derived
    # witness-only signer solely to demonstrate the fresh-message impact.
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O2 -Wall -Wextra -Wpedantic \
        -DSPEC_ALIGNED="$aligned" \
        -I"$base/include" -I"$base/test" $sources "$base/src/utils.c" \
        "$here/combined_extractor.c" -o "$base/combined_extractor"
}

compile_combined_sanitize() {
    profile=$1
    base="$here/spec-aligned/QingLuan-$profile"
    sources=""
    for source in $core_sources; do
        sources="$sources $base/src/$source"
    done
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O1 -g -Wall -Wextra -Wpedantic \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        -DSPEC_ALIGNED=1 \
        -I"$base/include" -I"$base/test" $sources "$base/src/utils.c" \
        "$here/combined_extractor.c" -o "$base/combined_extractor_sanitize"
}

for profile in 128 256 384 512; do
    compile_api spec-aligned 1 "$profile"
    compile_api pristine 0 "$profile"
    compile_standalone "$profile"
    compile_combined spec-aligned 1 "$profile"
    compile_combined pristine 0 "$profile"
done

compile_combined_sanitize 128
compile_combined_sanitize 512

"$here/spec-aligned/QingLuan-128/hostile_review_api" 32
"$here/spec-aligned/QingLuan-256/hostile_review_api" 8
"$here/spec-aligned/QingLuan-384/hostile_review_api" 4
"$here/spec-aligned/QingLuan-512/hostile_review_api" 4

"$here/pristine/QingLuan-128/hostile_review_api" 4
"$here/pristine/QingLuan-256/hostile_review_api" 4
"$here/pristine/QingLuan-384/hostile_review_api" 2
"$here/pristine/QingLuan-512/hostile_review_api" 2

"$here/spec-aligned/QingLuan-128/hostile_review_standalone" 4
"$here/spec-aligned/QingLuan-256/hostile_review_standalone" 4
"$here/spec-aligned/QingLuan-384/hostile_review_standalone" 2
"$here/spec-aligned/QingLuan-512/hostile_review_standalone" 2

for profile in 128 256 384 512; do
    "$here/spec-aligned/QingLuan-$profile/combined_extractor"
    "$here/pristine/QingLuan-$profile/combined_extractor"
done

ASAN_OPTIONS=detect_leaks=0 \
    "$here/spec-aligned/QingLuan-128/combined_extractor_sanitize"
ASAN_OPTIONS=detect_leaks=0 \
    "$here/spec-aligned/QingLuan-512/combined_extractor_sanitize"

python3 "$here/success_probability.py"
python3 "$here/rollback_probability.py"
python3 "$here/xof512_state_check.py"

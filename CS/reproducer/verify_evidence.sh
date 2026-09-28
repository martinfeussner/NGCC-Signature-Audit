#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
build=$("$here/build.sh")
evidence="$here/evidence"

(cd "$evidence" && sha256sum --check SHA256SUMS)
"$python" "$here/scripts/check_posterior_quadratic.py"

normalized_hash() {
    tr -d '\r' < "$1" | sha256sum | awk '{print $1}'
}

test "$(normalized_hash "$here/reference/CS-128/cs.c")" = \
    ac771cc2f138158680d1504f92bf2398c3f8fc85b9a6137c8cebcaa18bf96ff0
test "$(normalized_hash "$here/reference/CS-128/sampling.c")" = \
    bfd6abad31099e2a045644d500d3d1df4f90ae98d50a5c10ebf0a79b0416f541

scratch=$(mktemp -d "${TMPDIR:-/tmp}/cs128-replay.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

"$build/cs128_reference_baseline" --recover-d "$scratch/coarse" \
    "$evidence/stage1_state_1.bin" \
    "$evidence/stage1_state_2.bin" \
    "$evidence/stage1_state_3.bin" \
    "$evidence/stage1_state_4.bin" > "$scratch/stage1.txt"
cmp "$scratch/coarse.raw" "$evidence/allref_coarse.raw"
cmp "$scratch/coarse.quant" "$evidence/allref_coarse.quant"

"$python" "$here/scripts/scan_public_ladder.py" \
    "$build/cs128_reference_refinement" \
    "$scratch/result.txt" \
    "$scratch/previous.txt" \
    "$evidence/stage2a_state_1.bin" \
    "$evidence/stage2a_state_2.bin" \
    "$evidence/stage2b_state_1.bin" > "$scratch/public-ladder.txt"

# Replace every secret-dependent diagnostic truth array with unrelated values.
# The first public stopping point, completed key, and forgery must be unchanged.
"$python" "$here/scripts/scan_public_ladder.py" \
    "$build/cs128_reference_refinement_poison_control" \
    "$scratch/poison-result.txt" \
    "$scratch/poison-previous.txt" \
    "$evidence/stage2a_state_1.bin" \
    "$evidence/stage2a_state_2.bin" \
    "$evidence/stage2b_state_1.bin" > "$scratch/public-ladder-poison.txt"

cmp "$scratch/public-ladder.txt" "$evidence/public_ladder.txt"
cmp "$scratch/result.txt" "$evidence/cs128_public_ladder_result.txt"
cmp "$scratch/previous.txt" "$evidence/cs128_public_ladder_previous.txt"
cmp "$scratch/public-ladder-poison.txt" "$evidence/public_ladder_poison.txt"
cmp "$scratch/poison-result.txt" "$evidence/cs128_public_ladder_poison_result.txt"
cmp "$scratch/poison-previous.txt" "$evidence/cs128_public_ladder_poison_previous.txt"

normal_first=$(sed -n 's/^first_public_success=//p' "$scratch/public-ladder.txt")
poison_first=$(sed -n 's/^first_public_success=//p' "$scratch/public-ladder-poison.txt")
test -n "$normal_first"
test "$normal_first" = "$poison_first"
grep -Fqx 'equivalent_key_fresh_forgery=ACCEPT' "$scratch/result.txt"
grep -Fqx 'equivalent_key_fresh_forgery=ACCEPT' "$scratch/poison-result.txt"

printf 'CS-128 frozen evidence replay: PASS (first public success: %s refinement signatures)\n' \
    "$normal_first"

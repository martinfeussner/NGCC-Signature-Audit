#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
build=$("$here/build.sh")
runner="$here/scripts/run_reference_workers.py"
run="$here/build/full"

mkdir -p "$run"

# One million calibration signatures: four disjoint 250,000-signature streams.
"$python" "$runner" 250000 4 \
    "$build/cs128_reference_baseline" "$run" stage1 0

"$build/cs128_reference_baseline" --recover-d "$run/allref_coarse" \
    "$run/stage1_state_1.bin" \
    "$run/stage1_state_2.bin" \
    "$run/stage1_state_3.bin" \
    "$run/stage1_state_4.bin" > "$run/stage1_merge.txt"

# Begin refinement with two 500,000-signature streams.  Every worker saves
# cumulative states at 100,000-signature intervals, permitting a public
# sample-count ladder without retaining signatures.
"$python" "$runner" 500000 2 \
    "$build/cs128_reference_refinement" "$run" stage2a 100 \
    "$run/allref_coarse.raw"

# The third stream pauses after each 100,000 signatures.  At every pause, the
# normal and poisoned-diagnostic builds run the public completion and verifier
# test.  EOF stops the collector immediately after the first common success.
"$python" "$here/scripts/collect_until_public_success.py" \
    "$build/cs128_reference_refinement" \
    "$build/cs128_reference_refinement_poison_control" \
    "$run/allref_coarse.raw" \
    "$run" \
    "$run/stage2b_state_1.bin" \
    103 \
    "$run/stage2a_state_1.bin" \
    "$run/stage2a_state_2.bin"

normal_first=$(sed -n 's/^first_public_success=//p' "$run/public_ladder.txt")
poison_first=$(sed -n 's/^first_public_success=//p' "$run/public_ladder_poison.txt")
test -n "$normal_first"
test "$normal_first" = "$poison_first"

grep -Fqx 'equivalent_key_fresh_forgery=ACCEPT' \
    "$run/cs128_public_ladder_result.txt"

printf 'CS-128 live public ladder: PASS (refinement signatures: %s)\n' \
    "$normal_first"

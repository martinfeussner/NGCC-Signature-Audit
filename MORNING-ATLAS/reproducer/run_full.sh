#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=${PYTHON:-python3}
signatures=${1:-3000000}
key_id=${2:-4}
workers=${3:-4}
output=${4:-"$here/build/full-key-$key_id"}
shards=12

if (( signatures <= 0 || signatures % shards != 0 || workers < 1 || workers > shards )); then
    echo "usage: $0 [positive-signature-count-divisible-by-12] [key-id] [workers:1..12] [output-dir]" >&2
    exit 2
fi

make -C "$here" all
mkdir -p "$output/shards"
shard_size=$((signatures / shards))

for ((batch=0; batch<shards; batch+=workers)); do
    pids=()
    for ((slot=0; slot<workers && batch+slot<shards; slot++)); do
        index=$((batch + slot))
        start=$((index * shard_size))
        tag=$(printf '%07d' "$start")
        "$here/build/morning_faithful_constraints" \
            "$shard_size" "$key_id" "$output/shards/$tag.bin" \
            - hint-key "$start" >"$output/shards/$tag.log" 2>&1 &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
done

shard_files=()
for ((index=0; index<shards; index++)); do
    start=$((index * shard_size))
    tag=$(printf '%07d' "$start")
    shard_files+=("$output/shards/$tag.bin")
done
"$python_command" "$here/morning_merge_constraints.py" \
    "$output/constraints.bin" "${shard_files[@]}"

"$here/build/morning_faithful_hint_constraints" \
    20000 "$key_id" "$output/hints.bin"
"$python_command" "$here/morning_hint_minimax.py" \
    "$output/hints.bin" --output "$output/t0-estimate.npz"
"$python_command" "$here/morning_hint_integer_complete.py" \
    "$output/hints.bin" "$output/t0-estimate.npz" \
    --output "$output/t0-integer.npz"
"$python_command" "$here/npz_to_text.py" \
    "$output/t0-integer.npz" integer "$output/recovered-t0.txt"
"$here/build/morning_public_lwr_export" \
    "$output/hints.bin" "$output/recovered-t0.txt" "$output/public-lwr.bin"

"$python_command" "$here/morning_constraint_radial_lp.py" \
    "$output/constraints.bin" --outer 10 --output "$output/radial.npz"
"$python_command" "$here/morning_constraint_integer_completion.py" \
    "$output/constraints.bin" "$output/radial.npz" \
    --lwr "$output/public-lwr.bin" --time-limit 20 \
    --output "$output/integer-baseline.npz"
"$python_command" "$here/morning_lwr_lattice_block_ladder.py" \
    "$output/constraints.bin" "$output/radial.npz" \
    "$output/integer-baseline.npz" "$output/public-lwr.bin" \
    --samples 64 --secret-scale 18 --embedding-scale 1 \
    --bkz-block-sizes 10 20 --bkz-loops 2 \
    --output "$output/lattice-recovery.npz"
"$python_command" "$here/npz_to_text.py" \
    "$output/lattice-recovery.npz" secret "$output/recovered-s1.txt"

"$here/build/morning_equivalent_key_forge" \
    "$output/hints.bin" "$output/recovered-s1.txt" \
    "$output/recovered-t0.txt" "$here/evidence/morning_fresh_message.txt" \
    "$output/forgery.bin" "$output/equivalent-sk.bin"

echo "MORNING-ATLAS full recovery: PASS ($output)"

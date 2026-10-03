#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

sha256sum -c IMMUTABLE.SHA256SUMS

rm -rf work build
mkdir -p work build
cp scripts/hostile_complexity.py scripts/toy_spec_verifier.py \
  scripts/full_toy_forgery.py scripts/full_parameter_forc_splice.py work/

python3 work/hostile_complexity.py > work/hostile_complexity.stdout
python3 work/toy_spec_verifier.py > work/toy_spec.stdout
python3 work/full_toy_forgery.py > work/full_toy.stdout
python3 work/full_parameter_forc_splice.py > work/full_parameter_forc_splice.stdout
python3 scripts/replay_spec_repairs.py --output build/spec-repair-replay \
  > work/spec_repair_replay.json

cmp work/hostile_complexity.json expected/hostile_complexity.json
cmp work/hostile_complexity.stdout expected/hostile_complexity.json
cmp work/toy_spec_results.json expected/toy_spec_results.json
cmp work/toy_spec.stdout expected/toy_spec_results.json
cmp work/toy_results.json expected/full_toy_results.json
cmp work/full_toy.stdout expected/full_toy_results.json
cmp work/full_parameter_forc_splice.json expected/full_parameter_forc_splice.json
cmp work/full_parameter_forc_splice.stdout expected/full_parameter_forc_splice.json
cmp work/spec_repair_replay.json expected/spec_repair_replay.json

src=build/spec-repair-replay/submitted-256f
cc -O2 -std=c99 -Wall -Wextra -I"$src" \
  native_check.c "$src/sign.c" "$src/address.c" "$src/auxfunc.c" \
  "$src/drng.c" "$src/hash_sm3.c" "$src/merkle.c" "$src/fors.c" \
  "$src/randombytes.c" "$src/thash_sm3_simple.c" "$src/utils.c" \
  "$src/utilsx1.c" "$src/wots.c" "$src/wotsx1.c" \
  -o build/native_check
./build/native_check > work/native_results.json
cmp work/native_results.json expected/native_results.json

python3 scripts/validate_release.py --work work > work/validation_results.json
cmp work/validation_results.json expected/validation_results.json

echo 'cedrus_alpha_forc_accumulation_reproducer=PASS'

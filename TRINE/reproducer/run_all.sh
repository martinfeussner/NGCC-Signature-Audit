#!/usr/bin/env bash
set -euo pipefail

BASE="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE"

if [[ "${1:-}" == "--validate-only" ]]; then
  python3 validator/validate.py
  sha256sum -c SHA256SUMS
  echo "validation=PASS"
  exit 0
fi

mkdir -p results/latest
make -j"${JOBS:-4}"

python3 scripts/resource_model.py \
  --trials 2000 --seed-bits 16 --rng-seed 362157788741 \
  --output results/latest/resource-model.json \
  > results/latest/resource-model.stdout &
pid_model=$!

python3 scripts/fixed_q64_exact.py \
  > results/latest/fixed_q64_exact.txt &
pid_q64=$!

/usr/bin/time -v bin/portable_balanced \
  > results/latest/portable-balanced.txt \
  2> results/latest/portable-balanced.time &
pid_portable_balanced=$!

/usr/bin/time -v bin/portable_shortsig \
  > results/latest/portable-shortsig.txt \
  2> results/latest/portable-shortsig.time &
pid_portable_shortsig=$!

/usr/bin/time -v bin/partial_invariant 64 200 \
  > results/latest/partial-invariant.txt \
  2> results/latest/partial-invariant.time &
pid_partial=$!

bin/bench_seed_balanced > results/latest/seed-decode-balanced.txt
bin/bench_seed_shortsig > results/latest/seed-decode-shortsig.txt

/usr/bin/time -v bin/hostile_balanced \
  > results/latest/native-balanced.jsonl \
  2> results/latest/native-balanced.time &
pid_balanced=$!

/usr/bin/time -v bin/hostile_shortsig \
  > results/latest/native-shortsig.jsonl \
  2> results/latest/native-shortsig.time &
pid_shortsig=$!

/usr/bin/time -v bin/full_entropy_balanced \
  > results/latest/full-entropy-balanced.txt \
  2> results/latest/full-entropy-balanced.time &
pid_full_balanced=$!

/usr/bin/time -v bin/full_entropy_shortsig \
  > results/latest/full-entropy-shortsig.txt \
  2> results/latest/full-entropy-shortsig.time &
pid_full_shortsig=$!

wait "$pid_model" "$pid_q64" "$pid_portable_balanced" \
     "$pid_portable_shortsig" "$pid_partial" "$pid_balanced" \
     "$pid_shortsig" "$pid_full_balanced" "$pid_full_shortsig"

python3 validator/validate.py --check-latest
sha256sum -c SHA256SUMS
echo "validation=PASS"

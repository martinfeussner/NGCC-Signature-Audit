#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

./build.sh
rm -rf work/all-levels
mkdir -p work/all-levels

expect_failure() {
  set +e
  "$@"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || { echo "negative control unexpectedly succeeded" >&2; exit 90; }
}

for level in 160 256 384 512; do
  out="work/all-levels/$level"
  mkdir -p "$out"
  echo "level=$level phase=generate"
  /usr/bin/time -f 'generate wall=%e maxrss_kib=%M' \
    ./build/generate_pair "$level" inputs/query-message.bin \
      inputs/different-message.bin "$out" positive \
      >"$out/generate.json" 2>"$out/generate.time"
  echo "level=$level phase=recover-and-forge"
  /usr/bin/time -f 'attack wall=%e maxrss_kib=%M' \
    ./build/recover_and_forge "$level" "$out/public-key.bin" \
      inputs/query-message.bin "$out/honest-s.sig" "$out/honest-f.sig" \
      inputs/fresh-message.bin "$out/recovered-witness.bin" \
      "$out/forgery-s.sig" >"$out/recovery.json" 2>"$out/attack.time"
  ./build/untouched_verify "$level" "$out/public-key.bin" \
    inputs/fresh-message.bin "$out/forgery-s.sig" \
    >"$out/pristine-fresh.log"
  expect_failure ./build/untouched_verify "$level" "$out/public-key.bin" \
    inputs/query-message.bin "$out/forgery-s.sig"
  expect_failure ./build/untouched_verify "$level" "$out/public-key.bin" \
    inputs/wrong-message.bin "$out/forgery-s.sig"
  cat "$out/generate.json" "$out/recovery.json" "$out/generate.time" \
    "$out/attack.time" "$out/pristine-fresh.log"
  echo "level=$level result=pass"
done

printf 'all_levels_reproducer=pass\n'

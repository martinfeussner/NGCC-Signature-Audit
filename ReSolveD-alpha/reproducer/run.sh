#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

./build.sh
rm -rf work/160
mkdir -p work/160

expect_failure() {
  label=$1
  shift
  set +e
  "$@"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    printf '%s unexpectedly succeeded\n' "$label" >&2
    exit 90
  fi
  printf '%s=reject(rc=%s)\n' "$label" "$rc"
}

./build/generate_pair 160 inputs/query-message.bin inputs/different-message.bin \
  work/160 full | tee work/160/generate.json

# This process receives only public data: pk, message, and the two signatures.
./build/recover_and_forge 160 work/160/public-key.bin inputs/query-message.bin \
  work/160/honest-s.sig work/160/honest-f.sig inputs/fresh-message.bin \
  work/160/recovered-witness.bin work/160/forgery-s.sig \
  | tee work/160/recovery.json

# Final acceptance is decided by a binary linked only to untouched submitted
# verifier source.
./build/untouched_verify 160 work/160/public-key.bin inputs/fresh-message.bin \
  work/160/forgery-s.sig | tee work/160/pristine-fresh.log
expect_failure pristine_query_message ./build/untouched_verify 160 \
  work/160/public-key.bin inputs/query-message.bin work/160/forgery-s.sig
expect_failure pristine_wrong_message ./build/untouched_verify 160 \
  work/160/public-key.bin inputs/wrong-message.bin work/160/forgery-s.sig

# Cross-pair negative controls.  The recovery tool itself also requires the F
# opening alone to hide every challenged parent, rejects a one-bit witness
# mutation, and rejects the fresh forgery under the query message.
expect_failure different_message_pair ./build/recover_and_forge 160 \
  work/160/public-key.bin inputs/different-message.bin \
  work/160/different-message-s.sig work/160/honest-f.sig \
  inputs/fresh-message.bin work/160/no-witness-message.bin \
  work/160/no-forgery-message.sig
expect_failure different_rho_pair ./build/recover_and_forge 160 \
  work/160/public-key.bin inputs/query-message.bin \
  work/160/different-rho-s.sig work/160/honest-f.sig \
  inputs/fresh-message.bin work/160/no-witness-rho.bin \
  work/160/no-forgery-rho.sig
expect_failure different_key_pair ./build/recover_and_forge 160 \
  work/160/public-key-alt.bin inputs/query-message.bin \
  work/160/different-key-s.sig work/160/honest-f.sig \
  inputs/fresh-message.bin work/160/no-witness-key.bin \
  work/160/no-forgery-key.sig

sha256sum work/160/public-key.bin work/160/honest-s.sig work/160/honest-f.sig \
  work/160/recovered-witness.bin work/160/forgery-s.sig
printf 'minimal_reproducer=pass\n'

#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

seed_160=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
seed_large=5a313233343536373839304142434445465a313233343536373839304142434445465a313233343536373839304142434445465a31323334353637383930414243444546
seed_alt=00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100

rm -rf out/final
mkdir -p out/final/inputs
printf '%s\n' 'pristine-source Galas same-message recovery query' > out/final/inputs/chosen-message.txt
printf '%s\n' 'pristine-source Galas fresh-message forgery target' > out/final/inputs/fresh-message.txt
printf '%s\n' 'pristine-source Galas wrong-message control' > out/final/inputs/wrong-message.txt

(cd pristine-source && sha256sum -c ../PRISTINE_SOURCE.SHA256SUMS) \
  > out/final/source-integrity-before.log

expect_rc() {
    local expected=$1
    shift
    set +e
    "$@"
    local got=$?
    set -e
    if [[ $got -ne $expected ]]; then
        printf 'expected_rc=%s actual_rc=%s command=' "$expected" "$got" >&2
        printf '%q ' "$@" >&2
        printf '\n' >&2
        return 90
    fi
}

timed() {
    local label=$1
    shift
    /usr/bin/time -f "timing label=$label elapsed_s=%e user_s=%U sys_s=%S maxrss_kib=%M exit=%x" "$@"
}

run_level() {
    local level=$1 seed=$2 lb=$((level / 8))
    local dir="out/final/$level"
    local ps="build/pristine_${level}s" pf="build/pristine_${level}f"
    local os="build/oracle_${level}s" of="build/oracle_${level}f"
    local recover="build/recover_$level"
    mkdir -p "$dir"
    exec >"$dir/run.log" 2>&1
    export PS4='+ ${BASH_SOURCE##*/}:${LINENO}: '
    set -x

    # Both untouched submitted profiles derive byte-identical wrapper keys
    # from the same explicit KAT seed.
    timed "${level}s-pristine-keygen" "$ps" keygen "$seed" \
      "$dir/pk-pristine-s.bin" "$dir/sk-cache-pristine-s.bin"
    timed "${level}f-pristine-keygen" "$pf" keygen "$seed" \
      "$dir/pk-pristine-f.bin" "$dir/sk-cache-pristine-f.bin"
    cmp "$dir/pk-pristine-s.bin" "$dir/pk-pristine-f.bin"
    cmp "$dir/sk-cache-pristine-s.bin" "$dir/sk-cache-pristine-f.bin"
    head -c "$lb" "$dir/sk-cache-pristine-s.bin" > "$dir/x-from-cached-sk.bin"
    tail -c "$lb" "$dir/sk-cache-pristine-s.bin" > "$dir/k-from-cached-sk.bin"
    head -c "$lb" "$dir/pk-pristine-s.bin" > "$dir/x-from-pk.bin"
    cmp "$dir/x-from-cached-sk.bin" "$dir/x-from-pk.bin"

    # Repaired Algorithm-19 interface: pk=x||y, normative sk=k.
    timed "${level}s-oracle-keygen" "$os" keygen "$seed" \
      "$dir/pk-oracle-s.bin" "$dir/k-oracle-s.bin"
    timed "${level}f-oracle-keygen" "$of" keygen "$seed" \
      "$dir/pk-oracle-f.bin" "$dir/k-oracle-f.bin"
    cmp "$dir/pk-pristine-s.bin" "$dir/pk-oracle-s.bin"
    cmp "$dir/pk-pristine-s.bin" "$dir/pk-oracle-f.bin"
    cmp "$dir/k-from-cached-sk.bin" "$dir/k-oracle-s.bin"
    cmp "$dir/k-from-cached-sk.bin" "$dir/k-oracle-f.bin"

    # Full serialized transcript comparison for S and F. Galas signing in the
    # submitted/reference path is deterministic: fixed key and message fix
    # mu, rootKey, iv_pre, iv, all commitments, challenges, and ctr.
    timed "${level}s-pristine-sign-chosen" "$ps" sign \
      "$dir/sk-cache-pristine-s.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-s.bin"
    timed "${level}f-pristine-sign-chosen" "$pf" sign \
      "$dir/sk-cache-pristine-f.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-f.bin"
    timed "${level}s-oracle-sign-chosen" "$os" sign \
      "$dir/pk-oracle-s.bin" "$dir/k-oracle-s.bin" \
      out/final/inputs/chosen-message.txt "$dir/sig-oracle-s.bin"
    timed "${level}f-oracle-sign-chosen" "$of" sign \
      "$dir/pk-oracle-f.bin" "$dir/k-oracle-f.bin" \
      out/final/inputs/chosen-message.txt "$dir/sig-oracle-f.bin"
    cmp "$dir/sig-pristine-s.bin" "$dir/sig-oracle-s.bin"
    cmp "$dir/sig-pristine-f.bin" "$dir/sig-oracle-f.bin"

    # Untouched and repaired verifiers cross-accept both byte-identical paths.
    timed "${level}s-pristine-verify-pristine" "$ps" verify \
      "$dir/pk-pristine-s.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-s.bin"
    timed "${level}f-pristine-verify-pristine" "$pf" verify \
      "$dir/pk-pristine-f.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-f.bin"
    timed "${level}s-pristine-verify-oracle" "$ps" verify \
      "$dir/pk-pristine-s.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-oracle-s.bin"
    timed "${level}f-pristine-verify-oracle" "$pf" verify \
      "$dir/pk-pristine-f.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-oracle-f.bin"
    timed "${level}s-oracle-verify-pristine" "$os" verify \
      "$dir/pk-pristine-s.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-s.bin"
    timed "${level}f-oracle-verify-pristine" "$of" verify \
      "$dir/pk-pristine-f.bin" out/final/inputs/chosen-message.txt \
      "$dir/sig-pristine-f.bin"

    # Attack input consists only of signatures emitted through the original
    # submitted S/F interfaces. Recovery never receives pk or either secret.
    if [[ $level == 160 ]]; then
      expect_rc 5 "$recover" "$dir/sig-pristine-s.bin" \
        "$dir/sig-pristine-f.bin" "$dir/primary-only-should-not-exist.bin" \
        --primary-only
    fi
    timed "${level}-recover-from-pristine-transcripts" "$recover" \
      "$dir/sig-pristine-s.bin" "$dir/sig-pristine-f.bin" \
      "$dir/k-recovered.bin"
    cmp "$dir/k-recovered.bin" "$dir/k-from-cached-sk.bin"
    cmp "$dir/k-recovered.bin" "$dir/k-oracle-s.bin"

    # sign-norm only converts the normative k back to the submitted wrapper's
    # documented x||k cache. The cryptographic signing call is the untouched
    # submitted sig_sign implementation.
    timed "${level}f-pristine-sign-fresh-with-recovered-key" "$pf" sign-norm \
      "$dir/pk-pristine-f.bin" "$dir/k-recovered.bin" \
      out/final/inputs/fresh-message.txt "$dir/forgery-pristine-f.bin"
    timed "${level}f-pristine-verify-fresh-forgery" "$pf" verify \
      "$dir/pk-pristine-f.bin" out/final/inputs/fresh-message.txt \
      "$dir/forgery-pristine-f.bin"

    # Negative controls: message binding, public-key binding, and dependence
    # on the exact recovered key.
    expect_rc 4 "$pf" verify "$dir/pk-pristine-f.bin" \
      out/final/inputs/wrong-message.txt "$dir/forgery-pristine-f.bin"
    expect_rc 4 "$pf" verify "$dir/pk-pristine-f.bin" \
      out/final/inputs/fresh-message.txt "$dir/sig-pristine-f.bin"
    "$ps" keygen "$seed_alt" "$dir/pk-wrong.bin" "$dir/sk-cache-wrong.bin"
    tail -c "$lb" "$dir/sk-cache-wrong.bin" > "$dir/k-wrong.bin"
    expect_rc 4 "$pf" verify "$dir/pk-wrong.bin" \
      out/final/inputs/fresh-message.txt "$dir/forgery-pristine-f.bin"
    "$pf" sign-norm "$dir/pk-pristine-f.bin" "$dir/k-wrong.bin" \
      out/final/inputs/fresh-message.txt "$dir/sig-under-wrong-k.bin"
    expect_rc 4 "$pf" verify "$dir/pk-pristine-f.bin" \
      out/final/inputs/fresh-message.txt "$dir/sig-under-wrong-k.bin"

    sha256sum "$dir"/*.bin > "$dir/ARTIFACTS.sha256"
    printf 'level=%s transcript_s_equal=1 transcript_f_equal=1 exact_key_recovery=1 pristine_fresh_forgery_accept=1 wrong_message_reject=1 wrong_public_key_reject=1 wrong_secret_reject=1\n' "$level"
}

pids=()
for level in 160 256 384 512; do
    if [[ $level == 160 ]]; then seed=$seed_160; else seed=$seed_large; fi
    run_level "$level" "$seed" &
    pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then status=1; fi
done
if [[ $status -ne 0 ]]; then
    printf '%s\n' 'one or more level validations failed' >&2
    for level in 160 256 384 512; do
      printf '\n===== level %s =====\n' "$level" >&2
      tail -n 80 "out/final/$level/run.log" >&2 || true
    done
    exit 1
fi

(cd pristine-source && sha256sum -c ../PRISTINE_SOURCE.SHA256SUMS) \
  > out/final/source-integrity-after.log

{
  printf 'validation_started_utc=%s\n' "$started_utc"
  printf 'compiler='; "${CC:-cc}" --version 2>/dev/null | head -n 1 || cc --version | head -n 1
  printf 'seed_160=%s\nseed_256_384_512=%s\nseed_negative_control=%s\n' \
    "$seed_160" "$seed_large" "$seed_alt"
  for level in 160 256 384 512; do
    printf '\n===== level %s =====\n' "$level"
    cat "out/final/$level/run.log"
  done
  printf '\npristine_source_integrity_before=pass files=552\n'
  printf 'pristine_source_integrity_after=pass files=552\n'
  printf 'all_profiles_transcript_equivalence=pass profiles=8\n'
  printf 'all_levels_pristine_verifier_forgery=pass levels=4\n'
  printf 'validation_completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > out/final/validation.log

cat out/final/validation.log

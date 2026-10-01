#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
sha256sum -c PRISTINE_SOURCE.SHA256SUMS

cc_bin=${CC:-cc}
cflags=${CFLAGS:--O3 -march=native -Wno-psabi}
build="$here/build"
spec="$build/spec-core"

rm -rf "$build"
mkdir -p "$spec"
cp -R "$here/vendor/pristine/." "$spec/"

# This is the sole change to submitted cryptographic source.  It makes the
# signer hash the complete specification secret key seed_pk || seed_sk.
patch -s -d "$spec" -p1 < "$here/full-sk-coinhash.patch"

core_sources="bavc.c enc.c prg.c fields.c instances.c quicksilver.c rsd.c random_oracle.c tccr.c universal_hashing.c utils.c voleith_impl.c vole.c auxfunc.c"
spec_sources=
pristine_sources=
for source in $core_sources; do
  spec_sources="$spec_sources $spec/$source"
  pristine_sources="$pristine_sources $here/vendor/pristine/$source"
done

common="$cflags -std=c99 -Wall -Wextra -Wpedantic -DXOF_PSEUDO"

# shellcheck disable=SC2086
"$cc_bin" $common -I"$spec" $spec_sources \
  "$here/tools/generate_pair.c" -o "$build/generate_pair"
# shellcheck disable=SC2086
"$cc_bin" $common -I"$spec" $spec_sources \
  "$here/tools/recover_and_forge.c" -o "$build/recover_and_forge"
# The acceptance oracle below is linked only to the byte-for-byte submitted
# source under vendor/pristine, never to spec-core.
# shellcheck disable=SC2086
"$cc_bin" $common -I"$here/vendor/pristine" $pristine_sources \
  "$here/tools/untouched_verify.c" -o "$build/untouched_verify"

printf 'compiler=%s\n' "$("$cc_bin" --version | sed -n '1p')"
printf 'build=pass\n'

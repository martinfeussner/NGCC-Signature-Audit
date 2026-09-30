#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
build=$("$here/build.sh")

(cd "$here/evidence" && sha256sum --check SHA256SUMS)
"$python" "$here/check_envelope.py"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/rhyme-evidence.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
cp "$here/evidence/rhyme.pk" "$scratch/rhyme.pk"
cp "$here/evidence/rhyme.recovered" "$scratch/rhyme.recovered"

"$build/bin/pristine_forge" "$scratch/rhyme" | tee "$scratch/forge.log"
grep -Fqx \
    'exact=not-read public_relation=0 pack=0 valid=0 siglen=1372 norm_sq=28636' \
    "$scratch/forge.log"
grep -Fqx 'wrong_message=-1 perturbed_tail=-1 wrong_key=-1' \
    "$scratch/forge.log"
cmp "$scratch/rhyme.forgery" "$here/evidence/rhyme.forgery"
cmp "$scratch/rhyme.forgery-message" \
    "$here/evidence/rhyme.forgery-message"

printf '%s\n' 'Rhyme public-evidence replay: PASS'

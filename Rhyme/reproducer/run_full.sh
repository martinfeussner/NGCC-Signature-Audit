#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
variant=${1:-independent}

case "$variant" in
    independent)
        key_tag=0xbb67ae8584caa73b
        train=30000
        ;;
    reuse)
        key_tag=0x6a09e667f3bcc909
        train=40000
        ;;
    *)
        echo 'usage: ./run_full.sh [independent|reuse] [output-directory]' >&2
        exit 2
        ;;
esac

output=${2:-"$here/build/full-$variant"}
prefix="$output/rhyme"
build=$("$here/build.sh")

"$python" -c 'import numpy' >/dev/null 2>&1 || {
    echo 'Python with NumPy is required; set PYTHON=/path/to/python' >&2
    exit 2
}

mkdir -p "$output"
"$build/bin/${variant}_collect" 50000 "$prefix" "$key_tag" 50000 \
    > "$output/collect.log"

# The attack stage receives no file named *.secret.  The renamed file is used
# only after recovery to score exactness.
mv "$prefix.secret" "$prefix.secret.score"
"$build/bin/pristine_validate_oracle" "$prefix" 50000 \
    > "$output/pristine-validate.log"
"$python" "$here/recover.py" "$prefix" --gamma -1 --train "$train" \
    > "$output/recover.log"
"$build/bin/pristine_forge" "$prefix" > "$output/forge.log"

cmp "$prefix.recovered" "$prefix.secret.score"
grep -Fqx 'oracle=50000 pristine_accept=50000 verify_fail=0 unpack_fail=0' \
    "$output/pristine-validate.log"
grep -Fq 'public_relation=0 pack=0 valid=0 siglen=1372' \
    "$output/forge.log"
grep -Fqx 'wrong_message=-1 perturbed_tail=-1 wrong_key=-1' \
    "$output/forge.log"

cat "$output/collect.log"
cat "$output/pristine-validate.log"
cat "$output/recover.log"
cat "$output/forge.log"
sha256sum "$prefix.pk" "$prefix.records" "$prefix.recovered" \
    "$prefix.forgery" "$prefix.forgery-message"
printf 'Rhyme %s-tape full attack: PASS\n' "$variant"

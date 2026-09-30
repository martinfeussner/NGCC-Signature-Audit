#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
output=${1:-"$here/build/controls"}
key_tag=0xbb67ae8584caa73b
build=$("$here/build.sh")

"$python" -c 'import numpy' >/dev/null 2>&1 || {
    echo 'Python with NumPy is required; set PYTHON=/path/to/python' >&2
    exit 2
}

safe="$output/safe/rhyme"
mkdir -p "$output/safe"
"$build/bin/safe_collect" 50000 "$safe" "$key_tag" 50000 \
    > "$output/safe/collect.log"
mv "$safe.secret" "$safe.secret.score"
"$build/bin/pristine_validate_oracle" "$safe" 50000 \
    > "$output/safe/pristine-validate.log"
"$python" "$here/recover.py" "$safe" --gamma -1 --train 40000 \
    > "$output/safe/recover-blind.log"
if "$build/bin/pristine_forge" "$safe" > "$output/safe/forge.log"; then
    echo 'safe-M control unexpectedly forged' >&2
    exit 1
fi
grep -Fq 'public_relation=-1' "$output/safe/forge.log"
cp "$safe.secret.score" "$safe.secret"
"$python" "$here/recover.py" "$safe" --gamma -1 --train 40000 \
    > "$output/safe/posthoc-score.log"
rm "$safe.secret"
grep -Fq 'T=40000 rmse=0.971998 maxerr=2.318174 exact=399/1024' \
    "$output/safe/posthoc-score.log"

ungated="$output/ungated/rhyme"
mkdir -p "$output/ungated"
"$build/bin/ungated_collect" 50000 "$ungated" "$key_tag" 50000 \
    > "$output/ungated/collect.log"
mv "$ungated.secret" "$ungated.secret.score"
"$python" "$here/recover.py" "$ungated" --gamma -1 --train 30000 \
    > "$output/ungated/recover-blind.log"
cmp "$ungated.recovered" "$ungated.secret.score"
"$build/bin/pristine_forge" "$ungated" > "$output/ungated/forge.log"
grep -Fq 'public_relation=0 pack=0 valid=0 siglen=1372' \
    "$output/ungated/forge.log"

cat "$output/safe/collect.log"
cat "$output/safe/pristine-validate.log"
cat "$output/safe/posthoc-score.log"
cat "$output/safe/forge.log"
cat "$output/ungated/collect.log"
cat "$output/ungated/recover-blind.log"
cat "$output/ungated/forge.log"
printf '%s\n' 'Rhyme same-key controls: PASS'

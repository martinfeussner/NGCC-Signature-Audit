#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1

sha256sum -c SHA256SUMS

if [ "${1:-}" = "--validate-only" ]; then
    python3 scripts/validate_release.py --frozen-only
    echo 'validation=PASS'
    exit 0
fi

rm -rf build work results/latest
mkdir -p build work results/latest

python3 scripts/resource_model.py >work/resource-model.stdout
python3 scripts/independent_bounds.py >work/independent-bounds.stdout
python3 scripts/moment_check.py >work/moment-check.stdout
python3 scripts/toy_strict_forge.py >work/toy-strict-forge.stdout

cc_bin=${CC:-cc}
for set in 160f 160s; do
    src="vendor/submitted-$set"
    "$cc_bin" -O2 -std=c99 -Wall -Wextra -Werror -I"$src" \
        native_fors_splice.c \
        "$src/address.c" "$src/auxfunc.c" "$src/hash_sm3.c" \
        "$src/fors.c" "$src/thash_sm3_simple.c" "$src/utils.c" \
        "$src/utilsx1.c" -o "build/native_fors_splice_$set"
    "build/native_fors_splice_$set" \
        >"results/latest/native-fors-splice-$set.json"
done

python3 scripts/hostile_crosscheck.py >work/hostile-crosscheck.stdout

for result in \
    rigorous_complexity.json independent-bounds.json moment-check.json \
    toy-strict-forge.json native-fors-splice-160f.json \
    native-fors-splice-160s.json independent-audit.json
do
    cmp "results/latest/$result" "expected/$result"
done

python3 scripts/validate_release.py >work/validation.stdout
grep -q '"status": "PASS"' work/validation.stdout

sha256sum -c SHA256SUMS
echo 'validation=PASS'

#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=${PYTHON:-python3}
score=${1:-"$here/evidence/darts-key0-17m-scores.bin"}
matrix=${2:-"$here/evidence/darts-key0-public-matrix.txt"}
output=${3:-"$here/build/completion"}

if ! command -v flatter >/dev/null 2>&1; then
    echo 'flatter is required for a from-scratch reduction; see README.md' >&2
    exit 2
fi

mkdir -p "$output"
"$python_command" "$here/darts_binary_lattice.py" "$score" "$matrix" \
    --public-width-rung 2 --ladder-rung 2 --skip-lll \
    --basis-output "$output/raw.basis"
flatter -rhf 1.01 "$output/raw.basis" "$output/flatter.basis"
"$python_command" "$here/darts_binary_lattice.py" "$score" "$matrix" \
    --public-width-rung 2 --ladder-rung 2 --basis-input "$output/flatter.basis" \
    --skip-lll --float-type mpfr --precision 256 --bkz 20 --bkz-loops 2 \
    --basis-output "$output/bkz20.basis"
"$python_command" "$here/darts_binary_lattice.py" "$score" "$matrix" \
    --public-width-rung 2 --ladder-rung 2 --basis-input "$output/bkz20.basis" \
    --skip-lll --float-type mpfr --precision 256 --bkz 30 --bkz-loops 2 \
    --basis-output "$output/bkz30.basis" \
    --output-secret "$output/recovered-secret.txt"
test -s "$output/recovered-secret.txt"

#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=${PYTHON:-python3}

"$here/build.sh"
cd "$here"
(cd evidence && sha256sum --check SHA256SUMS)

"$python_command" darts_binary_lattice.py \
    evidence/darts-key0-17m-scores.bin \
    evidence/darts-key0-public-matrix.txt \
    --public-width-rung 2 --ladder-rung 2 \
    --basis-input evidence/darts-key0-17m-public-grid-bkz30.basis \
    --skip-lll --output-secret build/recovered-secret.txt

cmp build/recovered-secret.txt evidence/darts-key0-17m-recovered-secret.txt
build/darts_forge_from_secret \
    evidence/darts-key0-17m-scores.bin \
    build/recovered-secret.txt build/forgery.bin
cmp build/forgery.bin evidence/darts-key0-17m-forgery.bin
echo 'DARTS evidence replay: PASS'

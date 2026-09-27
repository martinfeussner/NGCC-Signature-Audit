#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$here/build/full-attack"}
mkdir -p "$output"

make -C "$here/ngcc-harness/sign-33" lib/libvdoo_128.so
make -C "$here/VDOO_structural_attack"
python3 "$here/VDOO_structural_attack/vdoo_end_to_end.py" \
    --pk "$here/VDOO_structural_attack/independent_seeded_public_key.bin" \
    --evidence-dir "$output"

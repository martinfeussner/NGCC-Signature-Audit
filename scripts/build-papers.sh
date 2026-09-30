#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$repo_root/build/papers"}
mkdir -p "$output"

for source in \
    BiT/BiT_Attack_Description.tex \
    Chinith/Chinith_Attack_Description.tex \
    CS/CS_Attack_Description.tex \
    DARTS/DARTS_Attack_Description.tex \
    Lynxer/Lynxer_Attack_Description.tex \
    MORNING-ATLAS/MORNING-ATLAS_Attack_Description.tex \
    Rhyme/Rhyme_Attack_Description.tex \
    Shuttle/Shuttle_Attack_Description.tex \
    Sigurd/Sigurd_Attack_Description.tex \
    SQIsign2D2/SQIsign2D2_Attack_Description.tex \
    SQIsignTriangle/SQIsignTriangle_Attack_Description.tex \
    UVW/UVW_Attack_Description.tex \
    VDOO/VDOO_Attack_Description.tex
do
    base=$(basename "$source" .tex)
    tectonic -X compile --outdir "$output" "$repo_root/$source"
    test -s "$output/$base.pdf"
done

"$repo_root/scripts/check-published-pdfs.sh"

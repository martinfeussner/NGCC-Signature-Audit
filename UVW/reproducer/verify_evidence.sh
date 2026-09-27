#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=${PYTHON:-python3}
build=$("$here/build.sh")
evidence="$here/evidence"

(cd "$evidence" && sha256sum --check SHA256SUMS)

scratch=$(mktemp -d "${TMPDIR:-/tmp}/uvw-replay.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

env OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-4}" \
    "$python" "$here/uvw_pair_likelihood.py" \
    "$evidence/uvw300.errors.bin" --out "$scratch/candidates.tsv"
cmp "$scratch/candidates.tsv" "$evidence/uvw300.candidates.tsv"

"$build/uvw_public_forgery" \
    "$evidence/uvw300.pk.bin" "$scratch/candidates.tsv" 1600 \
    "$scratch/forgery.api.bin"
cmp "$scratch/forgery.api.bin" "$evidence/uvw300.api-signature.bin"

bytes=$(wc -c < "$scratch/forgery.api.bin")
test "$bytes" -eq 1244
printf 'evidence_replay=PASS api_signature_bytes=%s\n' "$bytes"

#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")

cp "$here/sigurd_chunk_recovery.c" \
   "$harness/security/sigurd_chunk_recovery.c"
make -C "$harness/sign-24" clean-witness
make -C "$harness/sign-24" exploit

for level in 128 256 512; do
    for seed_id in 0 1; do
        "$harness/sign-24/bin/reproduce_recovery_$level" "$seed_id"
    done
done

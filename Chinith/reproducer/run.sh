#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")

cp "$here/chinith_universal_forgery.c" \
   "$harness/sign-05/reproduce_forgery.c"
make -C "$harness/sign-05" clean-witness
make -C "$harness/sign-05" exploit
make -C "$harness/sign-05" reproduce

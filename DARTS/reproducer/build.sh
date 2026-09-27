#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")
darts_source="$harness/sign-08/Implementations/Reference_Implementation/DARTS128"

make -C "$here" DARTS_DIR="$darts_source" all

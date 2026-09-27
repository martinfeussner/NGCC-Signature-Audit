#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
make -C "$here/ngcc-harness/sign-33" lib/libvdoo_128.so
python3 "$here/verify_evidence.py"

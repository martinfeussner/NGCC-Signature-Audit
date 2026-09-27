#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")
workers=${1:-4}

case "$workers" in
    ''|*[!0-9]*) echo "usage: $0 [workers:1..32]" >&2; exit 2 ;;
esac
if [ "$workers" -lt 1 ] || [ "$workers" -gt 32 ]; then
    echo "usage: $0 [workers:1..32]" >&2
    exit 2
fi

cp "$here/shuttle_covariance_recovery.c" \
   "$harness/security/shuttle_covariance_recovery.c"
make -C "$harness/sign-23" clean-witness
make -C "$harness/sign-23" exploit

for level in 128 256 512; do
    "$harness/sign-23/bin/reproduce_covariance_$level" "$workers"
done

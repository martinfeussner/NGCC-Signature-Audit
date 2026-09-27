#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
harness=$("$repo_root/scripts/fetch-ngcc-harness.sh")
keys=${1:-3}

case "$keys" in
    ''|*[!0-9]*) echo "usage: $0 [keys-per-level:1..100]" >&2; exit 2 ;;
esac
if [ "$keys" -lt 1 ] || [ "$keys" -gt 100 ]; then
    echo "usage: $0 [keys-per-level:1..100]" >&2
    exit 2
fi

for level in 1 2 5 6; do
    make -C "$here" HARNESS="$harness" LEVEL="$level"
    python3 "$here/forge_and_test.py" \
        --harness "$harness" --level "$level" --keys "$keys"
done

#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_command=${PYTHON:-python3}
signatures=${1:-17000000}
key_id=${2:-0}
workers=${3:-4}
output=${4:-"$here/build/full-key-$key_id"}

collection="$output/collection"
completion="$output/completion"

if ! command -v flatter >/dev/null 2>&1; then
    echo 'flatter is required for the full attack; see README.md' >&2
    exit 2
fi
"$python_command" -c 'import numpy, fpylll' || {
    echo 'the selected Python interpreter requires NumPy and fpylll' >&2
    exit 2
}

"$here/collect.sh" "$signatures" "$key_id" "$workers" "$collection"
"$here/complete_from_score.sh" \
    "$collection/scores.bin" "$collection/public-matrix.txt" "$completion"
"$here/build/darts_forge_from_secret" \
    "$collection/scores.bin" "$completion/recovered-secret.txt" \
    "$output/forgery.bin"

echo "DARTS full recovery: PASS ($output)"

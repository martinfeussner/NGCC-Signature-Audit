#!/bin/sh
set -eu

commit=32f381e40ae2eb35c83a454e8e59b17f44c26c7d
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
harness=${NGCC_HARNESS:-"$here/.cache/ngcc-harness"}

if [ ! -d "$harness/.git" ]; then
    if [ -n "${NGCC_HARNESS:-}" ]; then
        echo "NGCC_HARNESS is not a Git checkout: $harness" >&2
        exit 2
    fi
    mkdir -p "$(dirname -- "$harness")"
    git clone --filter=blob:none --no-checkout \
        https://github.com/ngcc-dev/ngcc-harness.git "$harness"
fi

if ! git -C "$harness" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$harness" fetch --depth 1 origin "$commit"
fi

actual=$(git -C "$harness" rev-parse HEAD)
if [ -n "${NGCC_HARNESS:-}" ]; then
    if [ "$actual" != "$commit" ]; then
        echo "NGCC_HARNESS must be at commit $commit (found $actual)" >&2
        exit 2
    fi
else
    git -C "$harness" checkout --quiet --detach "$commit"
fi

actual=$(git -C "$harness" rev-parse HEAD)
if [ "$actual" != "$commit" ]; then
    echo "unexpected ngcc-harness commit: $actual" >&2
    exit 2
fi

exec "$here/build_and_run.sh" "$harness/sign-25"

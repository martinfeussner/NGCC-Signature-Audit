#!/bin/sh
set -eu

commit=37ce9750cafd7ea0db0be255e4e8e02f10fe7841
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${NGCC_HARNESS:-"$repo_root/.cache/ngcc-harness"}

if [ ! -d "$destination/.git" ]; then
    mkdir -p "$(dirname -- "$destination")"
    git clone --filter=blob:none --no-checkout \
        https://github.com/ngcc-dev/ngcc-harness.git "$destination"
fi

if ! git -C "$destination" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$destination" fetch --depth 1 origin "$commit"
fi
git -C "$destination" checkout --quiet --detach "$commit"

actual=$(git -C "$destination" rev-parse HEAD)
if [ "$actual" != "$commit" ]; then
    echo "unexpected ngcc-harness commit: $actual" >&2
    exit 1
fi

printf '%s\n' "$destination"

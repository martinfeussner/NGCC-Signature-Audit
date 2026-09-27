#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
cache="$repo_root/.cache/bit"
archive=${BIT_ARCHIVE:-"$cache/BiT.zip"}
expected=698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d
url='https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip'
target=${1:-200000}
key_id=${2:-0}

case "$target:$key_id" in
    *[!0-9:]*) echo "usage: $0 [signatures] [key-id]" >&2; exit 2 ;;
esac

mkdir -p "$cache" "$here/build"
if [ ! -f "$archive" ]; then
    curl --fail --location --output "$archive" "$url"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status

source_root="$cache/source"
if [ ! -d "$source_root/Implementations/Reference_Implementation/BiT-128" ]; then
    mkdir -p "$source_root"
    unzip -q "$archive" -d "$source_root"
fi
bit_source="$source_root/Implementations/Reference_Implementation/BiT-128"

set --
for source in "$bit_source"/*.c; do
    case "$source" in
        */KAT_SIG.c) ;;
        *) set -- "$@" "$source" ;;
    esac
done

${CC:-cc} -O3 -std=gnu11 -Wall -Wextra -I"$bit_source" \
    "$here/bit_global_sign.c" "$@" -lm -o "$here/build/bit_global_sign"

"$here/build/bit_global_sign" "$target" "$target" 24 "$key_id"

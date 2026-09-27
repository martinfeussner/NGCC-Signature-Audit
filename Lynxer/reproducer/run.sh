#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/../.." && pwd)
cache="$repo_root/.cache/lynxer"
archive=${LYNXER_ARCHIVE:-"$cache/Lynxer.zip"}
expected=34d863f7df8979c4a5e27fcfe657ed54e81905115c0afc8ef749f50af432f928
url='https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Lynxer.zip'

mkdir -p "$cache" "$here/build"
if [ ! -f "$archive" ]; then
    curl --fail --location --output "$archive" "$url"
fi
printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status

source_root="$cache/source"
if [ ! -d "$source_root/Implementations/Reference_Implementation/Lynxer-256s" ]; then
    mkdir -p "$source_root"
    unzip -q "$archive" -d "$source_root"
fi

for parameter in 256s 256f 384s 384f 512s 512f; do
    candidate="$source_root/Implementations/Reference_Implementation/Lynxer-$parameter"
    set --
    for source in "$candidate"/*.c; do
        case "$source" in
            */KAT_SIG.c) ;;
            *) set -- "$@" "$source" ;;
        esac
    done
    output="$here/build/lynxer_forge_$parameter"
    ${CC:-cc} -O2 -march=native -std=c99 -DXOF_PSEUDO \
        -Wall -Wextra -I"$candidate" \
        "$here/lynxer_public_forgery.c" "$@" -o "$output"
    "$output"
done

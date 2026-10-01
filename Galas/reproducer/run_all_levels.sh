#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

out=${1:-out-all-levels}
seed=5a313233343536373839304142434445465a313233343536373839304142434445465a313233343536373839304142434445465a31323334353637383930414243444546

make extended
rm -rf "$out"
mkdir -p "$out"
printf '%s\n' 'all-level cross-variant recovery query' > "$out/message.txt"
printf '%s\n' 'all-level fresh-message forgery' > "$out/fresh.txt"
printf '%s\n' 'all-level wrong-message control' > "$out/wrong.txt"

for level in 256 384 512; do
    dir="$out/$level"
    mkdir -p "$dir"
    s="./build/oracle_${level}s"
    f="./build/oracle_${level}f"
    recover="./build/cross_variant_recover_${level}"

    "$s" keygen "$seed" "$dir/pk.bin" "$dir/sk-original.bin"
    "$s" sign "$dir/pk.bin" "$dir/sk-original.bin" "$out/message.txt" "$dir/sig-s.bin"
    "$f" sign "$dir/pk.bin" "$dir/sk-original.bin" "$out/message.txt" "$dir/sig-f.bin"
    "$s" verify "$dir/pk.bin" "$out/message.txt" "$dir/sig-s.bin"
    "$f" verify "$dir/pk.bin" "$out/message.txt" "$dir/sig-f.bin"

    "$recover" "$dir/sig-s.bin" "$dir/sig-f.bin" "$dir/sk-recovered.bin"
    cmp "$dir/sk-original.bin" "$dir/sk-recovered.bin"
    "$f" sign "$dir/pk.bin" "$dir/sk-recovered.bin" "$out/fresh.txt" "$dir/forgery-f.bin"
    "$f" verify "$dir/pk.bin" "$out/fresh.txt" "$dir/forgery-f.bin"
    if "$f" verify "$dir/pk.bin" "$out/wrong.txt" "$dir/forgery-f.bin"; then
        echo "Galas-$level wrong-message control unexpectedly accepted" >&2
        exit 1
    fi
    echo "level=$level exact_key_match=1 fresh_forgery_accept=1 wrong_message_reject=1"
    sha256sum "$dir/sk-original.bin" "$dir/sk-recovered.bin" \
        "$dir/sig-s.bin" "$dir/sig-f.bin" "$dir/forgery-f.bin"
done

echo "all_levels_reproducer=pass"

#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

out=${1:-out}
seed=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f

make clean all
mkdir -p "$out"

expect_rc() {
    expected=$1
    shift
    set +e
    "$@"
    got=$?
    set -e
    if [ "$got" -ne "$expected" ]; then
        echo "expected rc=$expected, got rc=$got: $*" >&2
        exit 90
    fi
}

./build/oracle_160s keygen "$seed" "$out/pk.bin" "$out/sk-original.bin"
./build/oracle_160s sign "$out/pk.bin" "$out/sk-original.bin" \
    inputs/chosen-message.txt "$out/sig-160s.bin"
./build/oracle_160f sign "$out/pk.bin" "$out/sk-original.bin" \
    inputs/chosen-message.txt "$out/sig-160f.bin"
./build/oracle_160s verify "$out/pk.bin" inputs/chosen-message.txt "$out/sig-160s.bin"
./build/oracle_160f verify "$out/pk.bin" inputs/chosen-message.txt "$out/sig-160f.bin"

# The F transcript alone omits its challenged tree-0 leaf and cannot recover the key.
expect_rc 5 ./build/cross_variant_recover "$out/sig-160s.bin" \
    "$out/sig-160f.bin" "$out/no-key.bin" --primary-only

# Adding the S opening supplies the same heap-indexed node.  Recovery does not read sk-original.
./build/cross_variant_recover "$out/sig-160s.bin" "$out/sig-160f.bin" \
    "$out/sk-recovered.bin"
cmp "$out/sk-original.bin" "$out/sk-recovered.bin"

# The recovered key creates an ordinary signature on a fresh message.
./build/oracle_160f sign "$out/pk.bin" "$out/sk-recovered.bin" \
    inputs/fresh-message.txt "$out/forgery-160f.bin"
./build/oracle_160f verify "$out/pk.bin" inputs/fresh-message.txt \
    "$out/forgery-160f.bin"

# Negative controls.
expect_rc 4 ./build/oracle_160f verify "$out/pk.bin" inputs/wrong-message.txt \
    "$out/forgery-160f.bin"
expect_rc 4 ./build/oracle_160f verify "$out/pk.bin" inputs/fresh-message.txt \
    "$out/sig-160f.bin"
./build/file_xor "$out/sk-recovered.bin" 0 "$out/sk-wrong.bin"
expect_rc 3 ./build/oracle_160f sign "$out/pk.bin" "$out/sk-wrong.bin" \
    inputs/fresh-message.txt "$out/should-not-sign.bin"
./build/file_xor "$out/forgery-160f.bin" 100 "$out/forgery-mutated.bin"
expect_rc 4 ./build/oracle_160f verify "$out/pk.bin" inputs/fresh-message.txt \
    "$out/forgery-mutated.bin"
expect_rc 1 ./build/cross_variant_recover "$out/sig-160s.bin" \
    "$out/forgery-160f.bin" "$out/nonmatching-message-key.bin"

./build/coverage_analysis
sha256sum "$out/pk.bin" "$out/sk-original.bin" "$out/sk-recovered.bin" \
    "$out/sig-160s.bin" "$out/sig-160f.bin" "$out/forgery-160f.bin"
echo "minimal_reproducer=pass"

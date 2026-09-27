#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
make -C "$here" all
cd "$here"
(cd evidence && sha256sum --check SHA256SUMS)

build/morning_verify_forgery \
    evidence/key4-public-key.bin evidence/morning_fresh_message.txt \
    evidence/morning-real-key4-forgery.bin

build/morning_equivalent_key_forge \
    evidence/key4-hint-header.bin \
    evidence/morning-real-key4-s1-public.txt \
    evidence/morning-t0-key4-20k-public.txt \
    evidence/morning_fresh_message.txt \
    build/reproduced-forgery.bin build/reproduced-equivalent-sk.bin
cmp build/reproduced-forgery.bin evidence/morning-real-key4-forgery.bin
cmp build/reproduced-equivalent-sk.bin evidence/morning-real-key4-equivalent-sk.bin
echo 'MORNING-ATLAS evidence replay: PASS'

#!/usr/bin/env python3
"""Check the QingLuan-512 counter-XOF post-key-state ceiling independently."""

import hashlib
import struct

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]
MASK = (1 << 32) - 1


def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK if n else x


def p0(x):
    return x ^ rol(x, 9) ^ rol(x, 17)


def p1(x):
    return x ^ rol(x, 15) ^ rol(x, 23)


def compress(state, block):
    assert len(block) == 64
    w = list(struct.unpack(">16I", block)) + [0] * 52
    for j in range(16, 68):
        w[j] = (p1(w[j - 16] ^ w[j - 9] ^ rol(w[j - 3], 15)) ^
                rol(w[j - 13], 7) ^ w[j - 6]) & MASK
    wp = [(w[j] ^ w[j + 4]) & MASK for j in range(64)]
    a, b, c, d, e, f, g, h = state
    for j in range(64):
        tj = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = rol((rol(a, 12) + e + rol(tj, j)) & MASK, 7)
        ss2 = ss1 ^ rol(a, 12)
        ff = (a ^ b ^ c) if j < 16 else ((a & b) | (a & c) | (b & c))
        gg = (e ^ f ^ g) if j < 16 else ((e & f) | ((~e) & g))
        tt1 = (ff + d + ss2 + wp[j]) & MASK
        tt2 = (gg + h + ss1 + w[j]) & MASK
        d, c, b, a = c, rol(b, 9), a, tt1
        h, g, f, e = g, rol(f, 19), e, p0(tt2) & MASK
    return [x ^ y for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def post_key_state(key):
    assert len(key) == 128
    state = IV[:]
    state = compress(state, key[:64])
    return compress(state, key[64:])


def block_from_state(state, counter):
    suffix = counter.to_bytes(4, "big") + b"\x80"
    suffix += b"\x00" * (56 - len(suffix))
    suffix += (132 * 8).to_bytes(8, "big")
    assert len(suffix) == 64
    final = compress(state[:], suffix)
    return struct.pack(">8I", *final)


key = bytes(range(128))
state = post_key_state(key)
reconstructed = b""
direct = b""
for counter in range(8):
    expected = hashlib.new("sm3", key + counter.to_bytes(4, "big")).digest()
    obtained = block_from_state(state, counter)
    assert obtained == expected
    reconstructed += obtained
    direct += expected
assert reconstructed == direct and len(reconstructed) == 256
print(
    "PASS QingLuan-512: one 256-bit SM3 chaining state after the two "
    "complete 64-byte key blocks reconstructs all 256 tested XOF bytes"
)
print("post_key_state=" + struct.pack(">8I", *state).hex())
print("stream_sha256=" + hashlib.sha256(reconstructed).hexdigest())


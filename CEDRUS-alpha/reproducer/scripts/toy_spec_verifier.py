#!/usr/bin/env python3
"""Independent reduced CEDRUS-alpha/FORC verifier and mixing attack.

This deliberately does not import submitted code or proponent code.  It keeps
the exact FORC chain direction, per-coordinate Merkle authentication, full
bottom address, attacker-controlled serialized R, and a Merkle-authenticated
address-fixed FORC public key.  The final Merkle layer is a reduced stand-in
for the CEDRUS hypertree: the property under test is exactly that its signed
message, PK_FORC(A), is fixed at a fixed complete address A.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

NBYTES = 16
H = 4                 # complete bottom-address bits
AHEIGHT = 2           # each FORC tree has 2^AHEIGHT leaves
K = 4                 # FORC trees / digest coordinates
W = 4                 # digest positions 0,...,W-1; terminal is C(W)


def ro(tag: bytes, *parts: bytes, out: int = NBYTES) -> bytes:
    x = hashlib.shake_256(tag)
    for p in parts:
        x.update(len(p).to_bytes(4, "big"))
        x.update(p)
    return x.digest(out)


def enc(x: int, n: int = 4) -> bytes:
    return x.to_bytes(n, "big")


def secret(master: bytes, addr: int, i: int, x: int) -> bytes:
    return ro(b"FORC-PRF", master, enc(addr), enc(i), enc(x))


def step(node: bytes, addr: int, i: int, x: int, j: int) -> bytes:
    return ro(b"FORC-F", enc(addr), enc(i), enc(x), enc(j), node)


def advance(node: bytes, addr: int, i: int, x: int, start: int,
            stop: int) -> bytes:
    assert 0 <= start <= stop
    for j in range(start + 1, stop + 1):
        node = step(node, addr, i, x, j)
    return node


def leaf(master: bytes, addr: int, i: int, x: int) -> bytes:
    return advance(secret(master, addr, i, x), addr, i, x, 0, W)


def mh(addr: int, i: int, level: int, index: int,
       left: bytes, right: bytes) -> bytes:
    return ro(b"FORC-H", enc(addr), enc(i), enc(level), enc(index), left, right)


def forc_levels(master: bytes, addr: int, i: int) -> list[list[bytes]]:
    levels = [[leaf(master, addr, i, x) for x in range(1 << AHEIGHT)]]
    for level in range(1, AHEIGHT + 1):
        prev = levels[-1]
        levels.append([
            mh(addr, i, level, j, prev[2*j], prev[2*j+1])
            for j in range(len(prev)//2)
        ])
    return levels


def forc_auth(master: bytes, addr: int, i: int, x: int) -> list[bytes]:
    levels = forc_levels(master, addr, i)
    out = []
    pos = x
    for level in range(AHEIGHT):
        out.append(levels[level][pos ^ 1])
        pos //= 2
    return out


def forc_root_from_opening(addr: int, i: int, x: int, endpoint: bytes,
                           path: list[bytes]) -> bytes:
    node, pos = endpoint, x
    for level, sibling in enumerate(path, 1):
        parent = pos // 2
        if pos & 1:
            node = mh(addr, i, level, parent, sibling, node)
        else:
            node = mh(addr, i, level, parent, node, sibling)
        pos = parent
    return node


def pk_forc_from_roots(addr: int, roots: list[bytes]) -> bytes:
    return ro(b"FORC-TK", enc(addr), *roots)


def true_pk_forc(master: bytes, addr: int) -> bytes:
    return pk_forc_from_roots(
        addr, [forc_levels(master, addr, i)[-1][0] for i in range(K)])


def top_leaf(master: bytes, addr: int) -> bytes:
    return ro(b"HT-LEAF", enc(addr), true_pk_forc(master, addr))


def top_levels(master: bytes) -> list[list[bytes]]:
    levels = [[top_leaf(master, a) for a in range(1 << H)]]
    for level in range(1, H + 1):
        prev = levels[-1]
        levels.append([
            ro(b"HT-H", enc(level), enc(j), prev[2*j], prev[2*j+1])
            for j in range(len(prev)//2)
        ])
    return levels


def top_auth(master: bytes, addr: int) -> list[bytes]:
    levels = top_levels(master)
    out, pos = [], addr
    for level in range(H):
        out.append(levels[level][pos ^ 1])
        pos //= 2
    return out


def top_root_from_auth(addr: int, pkf: bytes, path: list[bytes]) -> bytes:
    node = ro(b"HT-LEAF", enc(addr), pkf)
    pos = addr
    for level, sibling in enumerate(path, 1):
        parent = pos // 2
        if pos & 1:
            node = ro(b"HT-H", enc(level), enc(parent), sibling, node)
        else:
            node = ro(b"HT-H", enc(level), enc(parent), node, sibling)
        pos = parent
    return node


def digest(R: bytes, message: bytes) -> tuple[int, list[tuple[int, int]]]:
    bits = H + K * (AHEIGHT + (W.bit_length() - 1))
    z = int.from_bytes(ro(b"HMSG", R, message, out=(bits + 7)//8), "little")
    coords = []
    shift = 0
    for _ in range(K):
        x = (z >> shift) & ((1 << AHEIGHT) - 1)
        shift += AHEIGHT
        ell = (z >> shift) & (W - 1)
        shift += W.bit_length() - 1
        coords.append((x, ell))
    addr = (z >> shift) & ((1 << H) - 1)
    return addr, coords


@dataclass
class Opening:
    x: int
    ell: int
    node: bytes
    path: list[bytes]


@dataclass
class Signature:
    R: bytes
    openings: list[Opening]
    suffix: list[bytes]


MASTER = ro(b"fixed-test-master", b"independent-hostile-review")
SKPRF = ro(b"fixed-test-prf", b"ordinary-hedged-signing")
PUBLIC_ROOT = top_levels(MASTER)[-1][0]
TEST_RNG = random.Random(0xCEDA160F)


def sign(message: bytes) -> Signature:
    # Fresh optrand on every ordinary signing call; callers cannot choose it.
    # Deterministic test RNG for reproducibility; every call gets a fresh,
    # independently sampled test value and the attack never chooses it.
    optrand = TEST_RNG.randbytes(NBYTES)
    R = ro(b"PRFMSG", SKPRF, optrand, message)
    addr, coords = digest(R, message)
    openings = []
    for i, (x, ell) in enumerate(coords):
        s = secret(MASTER, addr, i, x)
        node = advance(s, addr, i, x, 0, ell)
        openings.append(Opening(x, ell, node, forc_auth(MASTER, addr, i, x)))
    return Signature(R, openings, top_auth(MASTER, addr))


def verify(message: bytes, sig: Signature) -> bool:
    addr, coords = digest(sig.R, message)
    if len(sig.openings) != K or len(sig.suffix) != H:
        return False
    roots = []
    for i, ((x, ell), op) in enumerate(zip(coords, sig.openings)):
        if op.x != x or op.ell != ell or len(op.path) != AHEIGHT:
            return False
        endpoint = advance(op.node, addr, i, x, ell, W)
        roots.append(forc_root_from_opening(addr, i, x, endpoint, op.path))
    pkf = pk_forc_from_roots(addr, roots)
    return top_root_from_auth(addr, pkf, sig.suffix) == PUBLIC_ROOT


def main() -> None:
    queried: set[bytes] = set()
    buckets: dict[int, list[tuple[bytes, Signature, list[tuple[int,int]]]]] = {}
    signing_queries = 0
    forged = None
    donors_used = None
    target_message = None

    # Keep collecting ordinary signatures and trying independent fresh
    # candidates.  Tiny parameters make the complete attack immediate.
    while forged is None:
        msg = b"query-" + signing_queries.to_bytes(8, "big")
        queried.add(msg)
        sig = sign(msg)
        assert verify(msg, sig)
        addr, coords = digest(sig.R, msg)
        buckets.setdefault(addr, []).append((msg, sig, coords))
        signing_queries += 1

        if signing_queries < 24:
            continue
        for trial in range(256):
            candidate = (b"fresh-candidate-" + signing_queries.to_bytes(8, "big")
                         + trial.to_bytes(4, "big"))
            if candidate in queried:
                continue
            R = ro(b"attacker-chosen-R", candidate, TEST_RNG.randbytes(8))
            target_addr, target_coords = digest(R, candidate)
            bucket = buckets.get(target_addr, [])
            chosen = []
            for i, (tx, tell) in enumerate(target_coords):
                match = None
                for _m, dsig, _dc in bucket:
                    dop = dsig.openings[i]
                    if dop.x == tx and dop.ell <= tell:
                        match = dsig
                        break
                if match is None:
                    break
                chosen.append(match)
            if len(chosen) != K:
                continue
            ops = []
            for i, ((tx, tell), dsig) in enumerate(zip(target_coords, chosen)):
                dop = dsig.openings[i]
                node = advance(dop.node, target_addr, i, tx, dop.ell, tell)
                ops.append(Opening(tx, tell, node, list(dop.path)))
            forged = Signature(R, ops, list(bucket[0][1].suffix))
            donors_used = chosen
            target_message = candidate
            break

    assert target_message not in queried
    assert verify(target_message, forged)
    target_addr, target_coords = digest(forged.R, target_message)

    controls = {}
    controls["changed_message"] = not verify(target_message+b"!", forged)
    bad = copy.deepcopy(forged); bad.R = bytes([bad.R[0]^1]) + bad.R[1:]
    controls["changed_R"] = not verify(target_message, bad)
    bad = copy.deepcopy(forged); bad.openings[0].path[0] = bytes(
        [bad.openings[0].path[0][0]^1]) + bad.openings[0].path[0][1:]
    controls["changed_FORC_auth_node"] = not verify(target_message, bad)
    bad = copy.deepcopy(forged); bad.suffix[0] = bytes(
        [bad.suffix[0][0]^1]) + bad.suffix[0][1:]
    controls["changed_hypertree_suffix"] = not verify(target_message, bad)

    # Presenting C(ell+1) as though it were C(ell) attempts to traverse the
    # chain backwards; verification instead reaches C(W+1), hence rejects.
    bad = copy.deepcopy(forged)
    op = bad.openings[0]
    op.node = step(op.node, target_addr, 0, op.x, op.ell+1)
    controls["reversed_chain_direction"] = not verify(target_message, bad)

    # Substitute a same-coordinate opening generated under another complete
    # address.  Find one deterministically, generating more ordinary samples
    # if necessary.
    other = None
    for a, rows in buckets.items():
        if a != target_addr:
            other = rows[0][1]
            break
    assert other is not None
    bad = copy.deepcopy(forged); bad.openings[0] = copy.deepcopy(other.openings[0])
    controls["different_full_address_opening"] = not verify(target_message, bad)

    assert all(controls.values()), controls
    donor_messages = []
    for d in donors_used:
        for m, s, _ in buckets[target_addr]:
            if s is d:
                donor_messages.append(m.decode())
                break
    result = {
        "parameters": {"nbytes":NBYTES,"h":H,"a":AHEIGHT,"k":K,"w":W},
        "ordinary_hedged_signing_queries": signing_queries,
        "target_address": target_addr,
        "target_coordinates": target_coords,
        "target_message": target_message.decode(),
        "target_was_never_queried": target_message not in queried,
        "donor_messages": donor_messages,
        "donor_count_distinct": len(set(donor_messages)),
        "forgery_accepted": True,
        "negative_controls": controls,
    }
    out = Path(__file__).with_name("toy_spec_results.json")
    out.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

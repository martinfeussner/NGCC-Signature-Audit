#!/usr/bin/env python3
"""Full-parameter FORC-level coordinate-splice conformance test.

This is deliberately narrower than a full CEDRUS-alpha forgery.  It uses the
submitted (n,h,a,k,w') geometry, the Algorithms 13--18 address dependencies,
and a deterministic SHAKE256 ideal-primitive stand-in.  It constructs complete
FORC Merkle trees at one full address, obtains three valid digest openings,
mixes their coordinates, and checks the reconstructed FORC public key.  It
also repeats the check under the prose's shifted endpoint convention.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Params:
    name: str
    n: int
    h: int
    a: int
    k: int
    w: int


SETS = (
    Params("160s", 20, 68, 10, 16, 8),
    Params("160f", 20, 66, 7, 28, 4),
    Params("256s", 32, 67, 12, 23, 4),
    Params("256f", 32, 65, 8, 45, 2),
    Params("384s", 48, 65, 12, 38, 4),
    Params("384f", 48, 65, 10, 51, 2),
    Params("512s", 64, 65, 13, 47, 4),
    Params("512f", 64, 66, 10, 66, 4),
)


class Model:
    def __init__(self, p: Params, endpoint_steps: int):
        self.p = p
        self.endpoint_steps = endpoint_steps
        self.address = int.from_bytes(
            hashlib.shake_256(("address:" + p.name).encode()).digest((p.h + 7) // 8),
            "big",
        ) & ((1 << p.h) - 1)
        self.addr_bytes = self.address.to_bytes((p.h + 7) // 8, "big")
        self.sk_seed = hashlib.shake_256(("sk:" + p.name).encode()).digest(p.n)
        self.pub_seed = hashlib.shake_256(("pub:" + p.name).encode()).digest(p.n)
        self.calls = {"prf": 0, "chain": 0, "tree": 0, "compress": 0}

    def _xof(self, tag: bytes, payload: bytes) -> bytes:
        return hashlib.shake_256(tag + self.p.name.encode() + payload).digest(self.p.n)

    def secret(self, global_chain: int) -> bytes:
        self.calls["prf"] += 1
        return self._xof(
            b"FTS-PRF\x00",
            self.pub_seed + self.sk_seed + self.addr_bytes
            + global_chain.to_bytes(8, "big") + b"\x00" * 4,
        )

    def chain_step(self, node: bytes, global_chain: int, step: int) -> bytes:
        self.calls["chain"] += 1
        return self._xof(
            b"FTS-CHAIN\x00",
            self.pub_seed + self.addr_bytes + global_chain.to_bytes(8, "big")
            + step.to_bytes(4, "big") + node,
        )

    def chain(self, node: bytes, global_chain: int, start: int, steps: int) -> bytes:
        for step in range(start + 1, start + steps + 1):
            node = self.chain_step(node, global_chain, step)
        return node

    def tree_hash(self, left: bytes, right: bytes, height: int,
                  global_index: int) -> bytes:
        self.calls["tree"] += 1
        return self._xof(
            b"FTS-TREE\x00",
            self.pub_seed + self.addr_bytes + height.to_bytes(4, "big")
            + global_index.to_bytes(8, "big") + left + right,
        )

    def compress(self, roots: list[bytes]) -> bytes:
        self.calls["compress"] += 1
        return self._xof(b"FTS-ROOT\x00", self.pub_seed + self.addr_bytes + b"".join(roots))

    def tree_levels(self, coordinate: int) -> list[list[bytes]]:
        p = self.p
        B = 1 << p.a
        leaves = []
        for x in range(B):
            u = coordinate * B + x
            leaves.append(self.chain(self.secret(u), u, 0, self.endpoint_steps))
        levels = [leaves]
        for height in range(1, p.a + 1):
            previous = levels[-1]
            current = []
            for local_index in range(len(previous) // 2):
                global_index = coordinate * (B >> height) + local_index
                current.append(self.tree_hash(previous[2 * local_index],
                                              previous[2 * local_index + 1],
                                              height, global_index))
            levels.append(current)
        return levels

    def opening(self, coordinate: int, leaf: int, position: int,
                levels: list[list[bytes]]) -> dict:
        B = 1 << self.p.a
        u = coordinate * B + leaf
        node = self.chain(self.secret(u), u, 0, position)
        path = [levels[j][(leaf >> j) ^ 1] for j in range(self.p.a)]
        return {"node": node, "path": path}

    def root_from_opening(self, coordinate: int, leaf: int, position: int,
                          opening: dict) -> bytes:
        B = 1 << self.p.a
        u = coordinate * B + leaf
        remaining = self.endpoint_steps - position
        if remaining < 0:
            raise ValueError("position lies beyond endpoint")
        node = self.chain(opening["node"], u, position, remaining)
        global_index = u
        for height, sibling in enumerate(opening["path"], start=1):
            parent = global_index >> 1
            if global_index & 1:
                node = self.tree_hash(sibling, node, height, parent)
            else:
                node = self.tree_hash(node, sibling, height, parent)
            global_index = parent
        return node

    def pk_from_openings(self, coords: list[tuple[int, int]],
                         openings: list[dict]) -> bytes:
        roots = [self.root_from_opening(i, leaf, position, openings[i])
                 for i, (leaf, position) in enumerate(coords)]
        return self.compress(roots)


def encode_coords(p: Params, coords: list[tuple[int, int]]) -> bytes:
    width = p.a + int(math.log2(p.w))
    bits = []
    for leaf, position in coords:
        bits.extend((leaf >> j) & 1 for j in range(p.a))
        bits.extend((position >> j) & 1 for j in range(width - p.a))
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        out[i >> 3] |= bit << (i & 7)
    return bytes(out)


def decode_coords(p: Params, encoded: bytes) -> list[tuple[int, int]]:
    bits = [(encoded[i >> 3] >> (i & 7)) & 1
            for i in range(p.k * (p.a + int(math.log2(p.w))))]
    result = []
    offset = 0
    for _ in range(p.k):
        leaf = sum(bits[offset + j] << j for j in range(p.a))
        offset += p.a
        ell_bits = int(math.log2(p.w))
        position = sum(bits[offset + j] << j for j in range(ell_bits))
        offset += ell_bits
        result.append((leaf, position))
    return result


def run_convention(p: Params, endpoint_steps: int) -> dict:
    model = Model(p, endpoint_steps)
    B = 1 << p.a
    donor_count = 3
    donor_coords = [[] for _ in range(donor_count)]
    target_coords = []
    for i in range(p.k):
        target_leaf = (0x9E3779B1 * (i + 1) + 0xA5A5) % B
        owner = i % donor_count
        # All allowed positions retain the same order under either endpoint
        # convention.  Use the last allowed target and the first donor node.
        target_coords.append((target_leaf, p.w - 1))
        for d in range(donor_count):
            leaf = target_leaf if d == owner else (target_leaf + d + 1) % B
            position = 0 if d == owner else (d + i) % p.w
            donor_coords[d].append((leaf, position))

    # Exercise the exact Algorithm 16 bit ordering at full digest width.
    encoded = [encode_coords(p, coords) for coords in donor_coords]
    encoded_target = encode_coords(p, target_coords)
    assert all(decode_coords(p, x) == coords for x, coords in zip(encoded, donor_coords))
    assert decode_coords(p, encoded_target) == target_coords

    donor_openings = [[] for _ in range(donor_count)]
    canonical_roots = []
    for i in range(p.k):
        levels = model.tree_levels(i)
        canonical_roots.append(levels[-1][0])
        for d in range(donor_count):
            leaf, position = donor_coords[d][i]
            donor_openings[d].append(model.opening(i, leaf, position, levels))

    canonical_pk = model.compress(canonical_roots)
    donor_pks = [model.pk_from_openings(donor_coords[d], donor_openings[d])
                 for d in range(donor_count)]
    assert all(pk == canonical_pk for pk in donor_pks)

    mixed = []
    owners = []
    advanced = 0
    for i, (leaf, target_position) in enumerate(target_coords):
        owner = i % donor_count
        owners.append(owner)
        donor_leaf, donor_position = donor_coords[owner][i]
        assert donor_leaf == leaf and donor_position <= target_position
        u = i * B + leaf
        node = model.chain(donor_openings[owner][i]["node"], u,
                           donor_position, target_position - donor_position)
        advanced += target_position - donor_position
        mixed.append({"node": node, "path": list(donor_openings[owner][i]["path"])})
    mixed_pk = model.pk_from_openings(target_coords, mixed)
    assert mixed_pk == canonical_pk
    assert len(set(owners)) == donor_count

    def one_donor_covers(d: int) -> bool:
        return all(donor_coords[d][i][0] == target_coords[i][0]
                   and donor_coords[d][i][1] <= target_coords[i][1]
                   for i in range(p.k))

    # Authentication tamper.
    tampered = [{"node": x["node"], "path": list(x["path"])} for x in mixed]
    changed = bytearray(tampered[0]["path"][0]); changed[0] ^= 1
    tampered[0]["path"][0] = bytes(changed)
    auth_tamper_rejected = model.pk_from_openings(target_coords, tampered) != canonical_pk

    # Claim the last position while supplying the unadvanced position-zero node.
    unadvanced = [{"node": x["node"], "path": list(x["path"])} for x in mixed]
    owner0 = 0
    unadvanced[0] = {
        "node": donor_openings[owner0][0]["node"],
        "path": list(donor_openings[owner0][0]["path"]),
    }
    unadvanced_rejected = model.pk_from_openings(target_coords, unadvanced) != canonical_pk

    # The same bytes under a different complete address must not authenticate.
    wrong = Model(p, endpoint_steps)
    wrong.address ^= 1
    wrong.addr_bytes = wrong.address.to_bytes((p.h + 7) // 8, "big")
    wrong_address_rejected = wrong.pk_from_openings(target_coords, mixed) != canonical_pk

    assert auth_tamper_rejected and unadvanced_rejected and wrong_address_rejected
    assert not any(one_donor_covers(d) for d in range(donor_count))

    return {
        "address_bits": p.h,
        "authentication_nodes_per_component": p.a,
        "canonical_pk_sha256": hashlib.sha256(canonical_pk).hexdigest(),
        "chain_endpoint_position": endpoint_steps,
        "coordinate_count": p.k,
        "coordinate_donors_used": donor_count,
        "digest_bytes": len(encoded_target),
        "forward_chain_steps_used_by_splice": advanced,
        "forc_signature_bytes": p.k * (p.a + 1) * p.n,
        "hash_calls": model.calls,
        "mixed_pk_matches": True,
        "negative_controls": {
            "authentication_tamper_rejected": auth_tamper_rejected,
            "unadvanced_node_rejected": unadvanced_rejected,
            "wrong_complete_address_rejected": wrong_address_rejected,
            "whole_donor_noncoverage": not any(one_donor_covers(d)
                                                for d in range(donor_count)),
        },
    }


def main() -> None:
    results = {}
    for p in SETS:
        algorithmic = run_convention(p, p.w)
        prose_shifted = run_convention(p, p.w - 1)
        results[p.name] = {
            "parameters": {"n": p.n, "h": p.h, "a": p.a, "k": p.k, "w_prime": p.w},
            "algorithm_14_18_endpoint": algorithmic,
            "prose_shifted_endpoint": prose_shifted,
            "ordering_relation_identical": True,
            "status": "PASS",
        }
    output = {
        "experiment_scope": (
            "full submitted FORC dimensions and address geometry; deterministic "
            "ideal-primitive stand-in; FORC-level splice, not a full signature forgery"
        ),
        "all_eight_parameter_sets_pass": all(x["status"] == "PASS" for x in results.values()),
        "sets": results,
    }
    target = Path(__file__).resolve().parent.parent / "work" / "full_parameter_forc_splice.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(output, indent=2, sort_keys=True) + "\n"
    target.write_text(text)
    print(text, end="")


if __name__ == "__main__":
    main()

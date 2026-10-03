#!/usr/bin/env python3
"""Scaled end-to-end strict repaired-verifier FORS accumulation experiment.

This is an ideal-addressed-hash model of the relevant CEDRUS+C structure.  It
has one XMSS layer, strict WOTS+C membership, ordinary randomized signing, and
address-separated FORS/WOTS/Merkle hashes.  The attack only combines public
pieces from ordinary signatures and chooses the public R in a fresh forgery.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


N = 3                       # 24-bit nodes; collision accidents remain unlikely.
H = 5                       # 32 bottom WOTS/FORS addresses.
ADDR_COUNT = 1 << H
FORS_A = 2
FORS_B = 1 << FORS_A
FORS_K = 3
FORCED = 2
WOTS_WIDTHS = [4, 4, 4, 4]
WOTS_SUM = sum(w - 1 for w in WOTS_WIDTHS) // 2
ORDINARY_QUERIES = 240
SEED = 0xCEDC11


def enc(x: int, length: int = 4) -> bytes:
    return x.to_bytes(length, "big")


def shake(tag: bytes, *parts: bytes, out: int = N) -> bytes:
    h = hashlib.shake_256()
    h.update(len(tag).to_bytes(2, "big"))
    h.update(tag)
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return h.digest(out)


@dataclass
class ForsComponent:
    secret: bytes
    auth: list[bytes]
    source_query: int
    source_address: int
    source_index: int


@dataclass
class Signature:
    R: bytes
    hmsg_counter: int
    fors: list[ForsComponent]
    wots_counter: int
    wots_nodes: list[bytes]
    xmss_auth: list[bytes]


class ToyCedrusC:
    def __init__(self, seed: int):
        rng = random.Random(seed)
        self.sk_seed = rng.randbytes(N)
        self.sk_prf = rng.randbytes(N)
        self.pub_seed = rng.randbytes(N)
        self._rng = rng
        self.xmss_levels = self._build_xmss()
        self.root = self.xmss_levels[-1][0]
        self.pk = self.pub_seed + self.root

    def ah(self, tag: bytes, *parts: bytes) -> bytes:
        return shake(tag, self.pub_seed, *parts)

    def wots_sk(self, address: int, chain: int) -> bytes:
        return self.ah(b"WOTS-PRF", self.sk_seed, enc(address), enc(chain))

    def wots_chain(self, value: bytes, address: int, chain: int,
                   start: int, steps: int) -> bytes:
        out = value
        for step in range(start, start + steps):
            out = self.ah(b"WOTS-CHAIN", enc(address), enc(chain), enc(step), out)
        return out

    def wots_public_leaf(self, address: int) -> bytes:
        endpoints = []
        for chain, width in enumerate(WOTS_WIDTHS):
            secret = self.wots_sk(address, chain)
            endpoints.append(self.wots_chain(secret, address, chain, 0, width - 1))
        return self.ah(b"WOTS-PK", enc(address), b"".join(endpoints))

    def _build_xmss(self) -> list[list[bytes]]:
        levels = [[self.wots_public_leaf(address) for address in range(ADDR_COUNT)]]
        height = 0
        while len(levels[-1]) > 1:
            old = levels[-1]
            new = []
            for node in range(0, len(old), 2):
                new.append(self.ah(b"XMSS-NODE", enc(height + 1), enc(node // 2),
                                   old[node], old[node + 1]))
            levels.append(new)
            height += 1
        return levels

    def xmss_auth(self, address: int) -> list[bytes]:
        auth = []
        index = address
        for level in range(H):
            auth.append(self.xmss_levels[level][index ^ 1])
            index >>= 1
        return auth

    def xmss_root_from_auth(self, leaf: bytes, address: int,
                            auth: list[bytes]) -> bytes:
        node = leaf
        index = address
        for height, sibling in enumerate(auth, start=1):
            if index & 1:
                left, right = sibling, node
            else:
                left, right = node, sibling
            node = self.ah(b"XMSS-NODE", enc(height), enc(index >> 1), left, right)
            index >>= 1
        return node

    def fors_secret(self, address: int, tree: int, leaf: int) -> bytes:
        return self.ah(b"FORS-PRF", self.sk_seed, enc(address), enc(tree), enc(leaf))

    def fors_leaf(self, address: int, tree: int, leaf: int, secret: bytes) -> bytes:
        return self.ah(b"FORS-LEAF", enc(address), enc(tree), enc(leaf), secret)

    def fors_levels(self, address: int, tree: int) -> list[list[bytes]]:
        leaves = [self.fors_leaf(address, tree, leaf,
                                 self.fors_secret(address, tree, leaf))
                  for leaf in range(FORS_B)]
        levels = [leaves]
        for height in range(1, FORS_A + 1):
            old = levels[-1]
            new = []
            for node in range(0, len(old), 2):
                new.append(self.ah(b"FORS-NODE", enc(address), enc(tree), enc(height),
                                   enc(node // 2), old[node], old[node + 1]))
            levels.append(new)
        return levels

    def fors_component(self, address: int, tree: int, index: int,
                       source_query: int) -> ForsComponent:
        levels = self.fors_levels(address, tree)
        auth = []
        cursor = index
        for height in range(FORS_A):
            auth.append(levels[height][cursor ^ 1])
            cursor >>= 1
        return ForsComponent(self.fors_secret(address, tree, index), auth,
                             source_query, address, index)

    def fors_root_from_component(self, component: ForsComponent, address: int,
                                 tree: int, index: int) -> bytes:
        node = self.fors_leaf(address, tree, index, component.secret)
        cursor = index
        for height, sibling in enumerate(component.auth, start=1):
            if cursor & 1:
                left, right = sibling, node
            else:
                left, right = node, sibling
            node = self.ah(b"FORS-NODE", enc(address), enc(tree), enc(height),
                           enc(cursor >> 1), left, right)
            cursor >>= 1
        return node

    def fors_pk_from_sig(self, components: list[ForsComponent], address: int,
                         indices: tuple[int, ...]) -> bytes:
        roots = [self.fors_root_from_component(components[t], address, t, indices[t])
                 for t in range(FORS_K)]
        return self.ah(b"FORS-PK", enc(address), b"".join(roots))

    def hmsg(self, R: bytes, counter: int, message: bytes):
        total_bits = FORCED + FORS_A * FORS_K + H
        raw = shake(b"HMSG", R, self.pk, message, enc(counter),
                    out=(total_bits + 7) // 8)
        value = int.from_bytes(raw, "big") >> (8 * len(raw) - total_bits)
        rest_bits = FORS_A * FORS_K + H
        forced = value >> rest_bits
        rest = value & ((1 << rest_bits) - 1)
        address = rest & (ADDR_COUNT - 1)
        packed_indices = rest >> H
        indices = tuple(
            (packed_indices >> ((FORS_K - 1 - tree) * FORS_A)) & (FORS_B - 1)
            for tree in range(FORS_K)
        )
        return forced, indices, address

    def wots_target(self, address: int, counter: int, message_root: bytes):
        # 2 leading-zero bits followed by four two-bit base-4 digits.
        raw = shake(b"WOTS-ROOT", self.pub_seed, enc(address), enc(counter),
                    message_root, out=2)
        value = int.from_bytes(raw, "big") >> 6
        leading = value >> 8
        digit_word = value & 0xff
        digits = tuple((digit_word >> (6 - 2 * i)) & 3 for i in range(4))
        legal = leading == 0 and sum(digits) == WOTS_SUM
        return legal, digits

    def wots_sign(self, address: int, message_root: bytes):
        for counter in range(1 << 16):
            legal, digits = self.wots_target(address, counter, message_root)
            if legal:
                nodes = [self.wots_chain(self.wots_sk(address, chain), address,
                                         chain, 0, digits[chain])
                         for chain in range(len(WOTS_WIDTHS))]
                return counter, nodes
        raise RuntimeError("toy WOTS counter exhausted")

    def wots_leaf_from_sig(self, nodes: list[bytes], address: int,
                           counter: int, message_root: bytes,
                           strict: bool = True) -> bytes | None:
        legal, digits = self.wots_target(address, counter, message_root)
        if strict and not legal:
            return None
        endpoints = [self.wots_chain(nodes[chain], address, chain, digits[chain],
                                    WOTS_WIDTHS[chain] - 1 - digits[chain])
                     for chain in range(len(WOTS_WIDTHS))]
        return self.ah(b"WOTS-PK", enc(address), b"".join(endpoints))

    def sign(self, message: bytes, query_id: int) -> tuple[Signature, tuple[int, ...], int]:
        opt_rand = self._rng.randbytes(N)
        R = shake(b"PRF-MSG", self.sk_prf, opt_rand, message)
        for hctr in range(1 << 16):
            forced, indices, address = self.hmsg(R, hctr, message)
            if forced == 0:
                break
        else:
            raise RuntimeError("toy H_MSG counter exhausted")
        components = [self.fors_component(address, tree, indices[tree], query_id)
                      for tree in range(FORS_K)]
        fpk = self.fors_pk_from_sig(components, address, indices)
        wctr, wnodes = self.wots_sign(address, fpk)
        signature = Signature(R, hctr, components, wctr, wnodes,
                              self.xmss_auth(address))
        return signature, indices, address

    def verify(self, message: bytes, signature: Signature, strict: bool = True) -> bool:
        forced, indices, address = self.hmsg(signature.R, signature.hmsg_counter, message)
        if forced != 0:
            return False
        if len(signature.fors) != FORS_K:
            return False
        fpk = self.fors_pk_from_sig(signature.fors, address, indices)
        leaf = self.wots_leaf_from_sig(signature.wots_nodes, address,
                                       signature.wots_counter, fpk, strict)
        if leaf is None:
            return False
        return self.xmss_root_from_auth(leaf, address, signature.xmss_auth) == self.root


def main() -> None:
    scheme = ToyCedrusC(SEED)
    transcripts = []
    table = defaultdict(lambda: [dict() for _ in range(FORS_K)])
    vectors = defaultdict(set)
    suffixes = {}
    repeated_wots_equal = True

    for query in range(ORDINARY_QUERIES):
        message = b"ordinary-message-" + enc(query)
        signature, indices, address = scheme.sign(message, query)
        assert scheme.verify(message, signature, strict=True)
        transcripts.append((message, signature, indices, address))
        vectors[address].add(indices)
        for tree, index in enumerate(indices):
            table[address][tree].setdefault(index, signature.fors[tree])
        suffix = (signature.wots_counter, signature.wots_nodes, signature.xmss_auth)
        if address in suffixes:
            repeated_wots_equal &= suffixes[address] == suffix
        else:
            suffixes[address] = suffix

    assert repeated_wots_equal
    fresh_message = b"fresh-message-never-queried"
    assert all(message != fresh_message for message, *_ in transcripts)

    attack_trials = 0
    selected = None
    # The verifier cannot test whether R came from PRF_MSG, so the adversary
    # samples it directly.  Keep ctr=0 here; R alone supplies ample entropy.
    for nonce in range(1 << 24):
        attack_trials += 1
        R = shake(b"ATTACKER-R", enc(nonce))
        forced, indices, address = scheme.hmsg(R, 0, fresh_message)
        if forced != 0 or address not in suffixes:
            continue
        if indices in vectors[address]:
            continue
        if not all(indices[tree] in table[address][tree] for tree in range(FORS_K)):
            continue
        components = [table[address][tree][indices[tree]] for tree in range(FORS_K)]
        if len({component.source_query for component in components}) < 2:
            continue
        selected = (R, indices, address, components)
        break
    assert selected is not None
    R, target_indices, target_address, components = selected
    wctr, wnodes, xauth = suffixes[target_address]
    forged = Signature(R, 0, copy.deepcopy(components), wctr,
                       copy.deepcopy(wnodes), copy.deepcopy(xauth))
    assert scheme.verify(fresh_message, forged, strict=True)

    # Negative controls.
    changed_message_rejected = not scheme.verify(fresh_message + b"!", forged, strict=True)

    changed_R = copy.deepcopy(forged)
    changed_R.R = bytes([changed_R.R[0] ^ 1]) + changed_R.R[1:]
    changed_R_rejected = not scheme.verify(fresh_message, changed_R, strict=True)

    auth_tamper = copy.deepcopy(forged)
    old = auth_tamper.fors[0].auth[0]
    auth_tamper.fors[0].auth[0] = bytes([old[0] ^ 1]) + old[1:]
    auth_path_tamper_rejected = not scheme.verify(fresh_message, auth_tamper, strict=True)

    invalid_membership = copy.deepcopy(forged)
    for bad_counter in range(1 << 16):
        legal, _ = scheme.wots_target(target_address, bad_counter,
                                      scheme.fors_pk_from_sig(
                                          invalid_membership.fors,
                                          target_address, target_indices))
        if not legal:
            invalid_membership.wots_counter = bad_counter
            break
    invalid_membership_rejected = not scheme.verify(fresh_message, invalid_membership,
                                                     strict=True)

    other = next(item for item in transcripts if item[3] != target_address)
    cross_address_suffix = copy.deepcopy(forged)
    cross_address_suffix.wots_counter = other[1].wots_counter
    cross_address_suffix.wots_nodes = copy.deepcopy(other[1].wots_nodes)
    cross_address_suffix.xmss_auth = copy.deepcopy(other[1].xmss_auth)
    cross_address_suffix_rejected = not scheme.verify(fresh_message,
                                                       cross_address_suffix, strict=True)

    wrong_address_component = copy.deepcopy(forged)
    wrong_address_component.fors[0] = copy.deepcopy(other[1].fors[0])
    wrong_address_component_rejected = not scheme.verify(
        fresh_message, wrong_address_component, strict=True)

    controls = {
        "all_ordinary_signatures_strictly_verified": True,
        "changed_message_rejected": changed_message_rejected,
        "changed_R_rejected": changed_R_rejected,
        "fors_auth_path_tamper_rejected": auth_path_tamper_rejected,
        "illegal_wots_membership_rejected": invalid_membership_rejected,
        "cross_address_hypertree_suffix_rejected": cross_address_suffix_rejected,
        "wrong_address_fors_component_rejected": wrong_address_component_rejected,
    }
    assert all(controls.values())

    occupancies = Counter(address for *_, address in transcripts)
    covered_vectors = sum(
        math.prod(len(table[address][tree]) for tree in range(FORS_K))
        for address in table
    )
    output = {
        "experiment": "scaled strict CEDRUS+C FORS accumulation forgery",
        "seed": SEED,
        "parameters": {
            "n_bytes": N,
            "bottom_address_bits": H,
            "fors_height": FORS_A,
            "fors_trees": FORS_K,
            "hmsg_forced_zero_bits": FORCED,
            "wots_widths": WOTS_WIDTHS,
            "wots_fixed_sum": WOTS_SUM,
            "strict_wots_membership": True,
        },
        "ordinary_queries": ORDINARY_QUERIES,
        "distinct_addresses": len(occupancies),
        "maximum_address_occupancy": max(occupancies.values()),
        "covered_address_digest_pairs": covered_vectors,
        "repeated_same_address_wots_signatures_identical": repeated_wots_equal,
        "forgery": {
            "accepted_by_strict_verifier": True,
            "fresh_message": fresh_message.decode(),
            "target_address": target_address,
            "target_fors_indices": list(target_indices),
            "target_vector_absent_from_ordinary_transcripts_at_address": (
                target_indices not in vectors[target_address]
            ),
            "whole_forged_transcript_absent_from_ordinary_transcripts": all(
                forged != signature for _, signature, _, _ in transcripts
            ),
            "component_source_queries": [component.source_query for component in components],
            "distinct_component_sources": len({component.source_query for component in components}),
            "attacker_hmsg_trials": attack_trials,
            "attacker_varied_R_only": True,
        },
        "controls": controls,
        "scope": {
            "ordinary_independent_key": True,
            "ordinary_randomized_signing_queries": True,
            "fault_reset_or_repeated_randomness": False,
            "index_collapse_bug": False,
            "omitted_wots_membership": False,
        },
    }
    out = Path(__file__).resolve().parent.parent / "results" / "latest" / "toy-strict-forge.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

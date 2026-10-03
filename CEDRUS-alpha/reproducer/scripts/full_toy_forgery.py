#!/usr/bin/env python3
"""Reduced, complete CEDRUS-alpha verifier and transcript-mixing experiment.

This is deliberately tiny and is not an official parameter set.  It follows the
repaired Algorithms 3--21: FORC has forward-only chains, XMSS authenticates the
FORC public key, and H_msg selects the global hypertree leaf.  SHA-256/SHAKE are
used as deterministic toy primitives, truncated to 32-bit tree nodes.  This
copy entered the independent revalidation only after the PDF equations were
frozen; the attack and controls are re-run here rather than trusting prior
output.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import json
from pathlib import Path


N = 4
H = (2, 2)
D = len(H)
A = 2
K = 2
W_PRIME = 4
WOTS_W = (16,) * 10
WOTS_S = sum(x - 1 for x in WOTS_W) // 2
MD_BYTES = (K * (A + 2) + 7) // 8
TREE_BYTES = (sum(H) - H[0] + 7) // 8
LEAF_BYTES = (H[0] + 7) // 8

OTS_HASH = 0
OTS_PK = 1
XMSS_TREE = 2
FTS_TREE = 3
FTS_ROOT = 4
OTS_PRF = 5
FTS_PRF = 6
FTS_CHAIN = 7


def h32(data: bytes, outlen: int = N) -> bytes:
    return hashlib.sha256(data).digest()[:outlen]


def xof(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def addr(layer: int, tree: int, typ: int, keypair: int = 0,
         word6: int = 0, word7: int = 0) -> bytes:
    """The normative 4+12+4+4+4+4-byte address layout."""
    return (layer.to_bytes(4, "big") + tree.to_bytes(12, "big") +
            typ.to_bytes(4, "big") + keypair.to_bytes(4, "big") +
            word6.to_bytes(4, "big") + word7.to_bytes(4, "big"))


def compressed_addr(adrs: bytes) -> bytes:
    """The 22-byte ADRS_c layout used by the n <= 32 instantiations."""
    assert len(adrs) == 32
    return adrs[3:4] + adrs[8:16] + adrs[19:20] + adrs[20:32]


def tweak(pub_seed: bytes, adrs: bytes, data: bytes) -> bytes:
    return h32(pub_seed + bytes(64 - N) + compressed_addr(adrs) + data)


def prf(pub_seed: bytes, sk_seed: bytes, adrs: bytes) -> bytes:
    return h32(pub_seed + bytes(64 - N) + compressed_addr(adrs) + sk_seed)


@functools.cache
def count_suffix(caps: tuple[int, ...], total: int) -> int:
    if total < 0:
        return 0
    dp = [0] * (total + 1)
    dp[0] = 1
    for cap in caps:
        nxt = [0] * (total + 1)
        for old, ways in enumerate(dp):
            for digit in range(min(cap - 1, total - old) + 1):
                nxt[old + digit] += ways
        dp = nxt
    return dp[total]


@functools.cache
def constant_sum_encode(message: bytes) -> tuple[int, ...]:
    rank = int.from_bytes(message, "big")
    assert count_suffix(WOTS_W, WOTS_S) >= 1 << (8 * N)
    rem = WOTS_S
    out = []
    for pos, cap in enumerate(WOTS_W):
        for digit in range(min(cap - 1, rem) + 1):
            block = count_suffix(WOTS_W[pos + 1:], rem - digit)
            if rank >= block:
                rank -= block
            else:
                out.append(digit)
                rem -= digit
                break
        else:
            raise AssertionError("rank outside constant-sum code")
    assert rem == 0 and rank == 0 and sum(out) == WOTS_S
    return tuple(out)


class ToyCedrus:
    def __init__(self) -> None:
        self.sk_seed = bytes.fromhex("01020304")
        self.sk_prf = bytes.fromhex("11121314")
        self.pub_seed = bytes.fromhex("21222324")
        self.root = self.xmss_node(D - 1, 0, 0, H[-1])

    def chain(self, value: bytes, layer: int, tree: int, keypair: int,
              chain_no: int, start: int, steps: int) -> bytes:
        out = value
        for j in range(start, start + steps):
            out = tweak(self.pub_seed,
                        addr(layer, tree, OTS_HASH, keypair, chain_no, j), out)
        return out

    @functools.cache
    def wots_sk(self, layer: int, tree: int, keypair: int, chain_no: int) -> bytes:
        return prf(self.pub_seed, self.sk_seed,
                   addr(layer, tree, OTS_PRF, keypair, chain_no, 0))

    @functools.cache
    def wots_pk(self, layer: int, tree: int, keypair: int) -> bytes:
        ends = []
        for i, cap in enumerate(WOTS_W):
            sk = self.wots_sk(layer, tree, keypair, i)
            ends.append(self.chain(sk, layer, tree, keypair, i, 0, cap - 1))
        return tweak(self.pub_seed, addr(layer, tree, OTS_PK, keypair), b"".join(ends))

    def wots_sign(self, message: bytes, layer: int, tree: int,
                  keypair: int) -> list[bytes]:
        digits = constant_sum_encode(message)
        return [self.chain(self.wots_sk(layer, tree, keypair, i),
                           layer, tree, keypair, i, 0, digit)
                for i, digit in enumerate(digits)]

    def wots_pk_from_sig(self, sig: list[bytes], message: bytes, layer: int,
                         tree: int, keypair: int) -> bytes:
        if len(sig) != len(WOTS_W):
            raise ValueError("bad WOTS length")
        digits = constant_sum_encode(message)
        ends = [self.chain(sig[i], layer, tree, keypair, i, digits[i],
                           WOTS_W[i] - 1 - digits[i])
                for i in range(len(WOTS_W))]
        return tweak(self.pub_seed, addr(layer, tree, OTS_PK, keypair), b"".join(ends))

    @functools.cache
    def xmss_node(self, layer: int, tree: int, index: int, height: int) -> bytes:
        if height == 0:
            return self.wots_pk(layer, tree, index)
        left = self.xmss_node(layer, tree, 2 * index, height - 1)
        right = self.xmss_node(layer, tree, 2 * index + 1, height - 1)
        return tweak(self.pub_seed,
                     addr(layer, tree, XMSS_TREE, 0, height, index), left + right)

    def xmss_sign(self, message: bytes, layer: int, tree: int,
                  leaf: int) -> dict:
        auth = []
        for j in range(H[layer]):
            sibling = (leaf >> j) ^ 1
            auth.append(self.xmss_node(layer, tree, sibling, j))
        return {"wots": self.wots_sign(message, layer, tree, leaf), "auth": auth}

    def xmss_root_from_sig(self, sig: dict, message: bytes, layer: int,
                           tree: int, leaf: int) -> bytes:
        if len(sig.get("auth", [])) != H[layer]:
            raise ValueError("bad XMSS auth length")
        node = self.wots_pk_from_sig(sig["wots"], message, layer, tree, leaf)
        index = leaf
        for height, sibling in enumerate(sig["auth"], start=1):
            parent = index >> 1
            pair = node + sibling if index % 2 == 0 else sibling + node
            node = tweak(self.pub_seed,
                         addr(layer, tree, XMSS_TREE, 0, height, parent), pair)
            index = parent
        return node

    @functools.cache
    def forc_sk(self, tree: int, keypair: int, chain_no: int) -> bytes:
        return prf(self.pub_seed, self.sk_seed,
                   addr(0, tree, FTS_PRF, keypair, chain_no, 0))

    def forc_chain(self, value: bytes, tree: int, keypair: int,
                   chain_no: int, start: int, steps: int) -> bytes:
        out = value
        for j in range(start + 1, start + steps + 1):
            out = tweak(self.pub_seed,
                        addr(0, tree, FTS_CHAIN, keypair, chain_no, j), out)
        return out

    @functools.cache
    def forc_node(self, tree: int, keypair: int, index: int, height: int) -> bytes:
        if height == 0:
            sk = self.forc_sk(tree, keypair, index)
            return self.forc_chain(sk, tree, keypair, index, 0, W_PRIME)
        left = self.forc_node(tree, keypair, 2 * index, height - 1)
        right = self.forc_node(tree, keypair, 2 * index + 1, height - 1)
        return tweak(self.pub_seed,
                     addr(0, tree, FTS_TREE, keypair, height, index), left + right)

    @staticmethod
    def forc_coords(md: bytes) -> tuple[tuple[int, int], ...]:
        bits = [(md[i >> 3] >> (i & 7)) & 1 for i in range(K * (A + 2))]
        off = 0
        coords = []
        for _ in range(K):
            index = sum(bits[off + j] << j for j in range(A))
            off += A
            length = sum(bits[off + j] << j for j in range(2))
            off += 2
            coords.append((index, length))
        return tuple(coords)

    def forc_sign(self, md: bytes, tree: int, keypair: int) -> list[dict]:
        out = []
        for i, (index, length) in enumerate(self.forc_coords(md)):
            absolute = i * (1 << A) + index
            node = self.forc_chain(self.forc_sk(tree, keypair, absolute),
                                   tree, keypair, absolute, 0, length)
            auth = []
            for j in range(A):
                sibling = (index >> j) ^ 1
                auth.append(self.forc_node(tree, keypair,
                                           i * (1 << (A - j)) + sibling, j))
            out.append({"node": node, "auth": auth})
        return out

    def forc_pk_from_sig(self, sig: list[dict], md: bytes,
                         tree: int, keypair: int) -> bytes:
        if len(sig) != K:
            raise ValueError("bad FORC length")
        roots = []
        for i, (index, length) in enumerate(self.forc_coords(md)):
            if len(sig[i].get("auth", [])) != A:
                raise ValueError("bad FORC auth length")
            absolute = i * (1 << A) + index
            node = self.forc_chain(sig[i]["node"], tree, keypair,
                                   absolute, length, W_PRIME - length)
            global_index = absolute
            for height, sibling in enumerate(sig[i]["auth"], start=1):
                parent = global_index >> 1
                pair = node + sibling if global_index % 2 == 0 else sibling + node
                node = tweak(self.pub_seed,
                             addr(0, tree, FTS_TREE, keypair, height, parent), pair)
                global_index = parent
            roots.append(node)
        return tweak(self.pub_seed, addr(0, tree, FTS_ROOT, keypair), b"".join(roots))

    def ht_sign(self, message: bytes, tree: int, leaf: int) -> list[dict]:
        out = []
        node = message
        for layer in range(D):
            xsig = self.xmss_sign(node, layer, tree, leaf)
            out.append(xsig)
            node = self.xmss_root_from_sig(xsig, node, layer, tree, leaf)
            if layer + 1 < D:
                leaf = tree & ((1 << H[layer + 1]) - 1)
                tree >>= H[layer + 1]
        return out

    def ht_verify(self, message: bytes, sig: list[dict], tree: int,
                  leaf: int) -> bool:
        if len(sig) != D:
            return False
        node = message
        try:
            for layer in range(D):
                node = self.xmss_root_from_sig(sig[layer], node, layer, tree, leaf)
                if layer + 1 < D:
                    leaf = tree & ((1 << H[layer + 1]) - 1)
                    tree >>= H[layer + 1]
        except (KeyError, ValueError):
            return False
        return node == self.root

    def digest(self, R: bytes, message: bytes) -> bytes:
        return xof(R + self.pub_seed + self.root + message,
                   MD_BYTES + TREE_BYTES + LEAF_BYTES)

    @staticmethod
    def split_digest(digest: bytes) -> tuple[bytes, int, int]:
        md = digest[:MD_BYTES]
        tree = int.from_bytes(digest[MD_BYTES:MD_BYTES + TREE_BYTES], "big")
        tree &= (1 << (sum(H) - H[0])) - 1
        leaf = int.from_bytes(digest[-LEAF_BYTES:], "big") & ((1 << H[0]) - 1)
        return md, tree, leaf

    def sign(self, message: bytes, opt_rand: bytes) -> dict:
        R = h32(self.sk_prf + opt_rand + message)
        md, tree, leaf = self.split_digest(self.digest(R, message))
        fsig = self.forc_sign(md, tree, leaf)
        fpk = self.forc_pk_from_sig(fsig, md, tree, leaf)
        return {"R": R, "forc": fsig, "ht": self.ht_sign(fpk, tree, leaf)}

    def verify(self, message: bytes, sig: dict) -> bool:
        try:
            if len(sig["R"]) != N:
                return False
            md, tree, leaf = self.split_digest(self.digest(sig["R"], message))
            fpk = self.forc_pk_from_sig(sig["forc"], md, tree, leaf)
            return self.ht_verify(fpk, sig["ht"], tree, leaf)
        except (KeyError, ValueError, OverflowError):
            return False


def find_digest(model: ToyCedrus, source_coords, source_tree, source_leaf,
                relation: str):
    for trial in range(1, 2_000_000):
        R = trial.to_bytes(N, "big")
        message = b"fresh:" + trial.to_bytes(4, "big")
        md, tree, leaf = model.split_digest(model.digest(R, message))
        coords = model.forc_coords(md)
        if tree != source_tree or leaf != source_leaf:
            continue
        same_indices = all(coords[i][0] == source_coords[i][0] for i in range(K))
        if not same_indices:
            continue
        if relation == "forward":
            ok = all(coords[i][1] >= source_coords[i][1] for i in range(K))
            ok &= any(coords[i][1] > source_coords[i][1] for i in range(K))
        else:
            ok = any(coords[i][1] < source_coords[i][1] for i in range(K))
        if ok:
            return trial, R, message, md, tree, leaf, coords
    raise AssertionError("digest search exhausted")


def find_mixed_digest(model: ToyCedrus, records, tree: int, leaf: int):
    """Find a target covered coordinate-wise but by no single transcript."""
    queried = {record["message"] for record in records}
    for trial in range(1, 2_000_000):
        R = h32(b"mixed-R" + trial.to_bytes(4, "big"))
        message = b"mixed-fresh:" + trial.to_bytes(4, "big")
        if message in queried:
            continue
        md, got_tree, got_leaf = model.split_digest(model.digest(R, message))
        if (got_tree, got_leaf) != (tree, leaf):
            continue
        coords = model.forc_coords(md)
        donors = []
        for i, (target_index, target_length) in enumerate(coords):
            choices = [j for j, record in enumerate(records)
                       if record["coords"][i][0] == target_index and
                       record["coords"][i][1] <= target_length]
            if not choices:
                break
            donors.append(choices[0])
        if len(donors) != K or len(set(donors)) < 2:
            continue
        single_covers = any(
            all(record["coords"][i][0] == coords[i][0] and
                record["coords"][i][1] <= coords[i][1] for i in range(K))
            for record in records)
        if not single_covers:
            return trial, R, message, coords, donors
    raise AssertionError("mixed digest search exhausted")


def main() -> None:
    model = ToyCedrus()
    source_message = b"source transcript"
    source = model.sign(source_message, bytes.fromhex("31323334"))
    assert model.verify(source_message, source)
    source_md, source_tree, source_leaf = model.split_digest(
        model.digest(source["R"], source_message))
    source_coords = model.forc_coords(source_md)
    source_fpk = model.forc_pk_from_sig(
        source["forc"], source_md, source_tree, source_leaf)

    trial, R, target_message, target_md, target_tree, target_leaf, target_coords = \
        find_digest(model, source_coords, source_tree, source_leaf, "forward")
    forged = copy.deepcopy(source)
    forged["R"] = R
    for i in range(K):
        old_len = source_coords[i][1]
        new_len = target_coords[i][1]
        absolute = i * (1 << A) + source_coords[i][0]
        forged["forc"][i]["node"] = model.forc_chain(
            source["forc"][i]["node"], source_tree, source_leaf,
            absolute, old_len, new_len - old_len)

    assert target_message != source_message
    assert model.forc_pk_from_sig(
        forged["forc"], target_md, target_tree, target_leaf) == source_fpk
    assert model.verify(target_message, forged)

    unadvanced = copy.deepcopy(source)
    unadvanced["R"] = R
    assert model.forc_pk_from_sig(
        unadvanced["forc"], target_md, target_tree, target_leaf) != source_fpk
    assert not model.verify(target_message, unadvanced)

    back_trial, back_R, back_message, _, _, _, back_coords = \
        find_digest(model, source_coords, source_tree, source_leaf, "backward")
    backward_attempt = copy.deepcopy(source)
    backward_attempt["R"] = back_R
    assert not model.verify(back_message, backward_attempt)

    tampered = copy.deepcopy(forged)
    changed = bytearray(tampered["forc"][0]["auth"][0])
    changed[0] ^= 1
    tampered["forc"][0]["auth"][0] = bytes(changed)
    assert not model.verify(target_message, tampered)

    other = None
    other_message = None
    for i in range(1, 10000):
        candidate_message = b"splice:" + i.to_bytes(4, "big")
        candidate = model.sign(candidate_message, h32(b"optrand" + i.to_bytes(4, "big")))
        _, candidate_tree, _ = model.split_digest(model.digest(candidate["R"], candidate_message))
        if candidate_tree != source_tree:
            other, other_message = candidate, candidate_message
            break
    assert other is not None and model.verify(other_message, other)
    wrong_address_component = copy.deepcopy(source)
    wrong_address_component["forc"][0] = copy.deepcopy(other["forc"][0])
    assert not model.verify(source_message, wrong_address_component)
    spliced = copy.deepcopy(source)
    spliced["ht"][1] = copy.deepcopy(other["ht"][1])
    assert not model.verify(source_message, spliced)

    # Accumulate several signatures at the same global hypertree leaf.  The
    # target below is chosen so that each FORC coordinate is derivable from a
    # retained transcript, but no one transcript covers the whole target.
    records = [{"message": source_message, "sig": source,
                "coords": source_coords}]
    acquisition_queries = 0
    while len(records) < 24:
        acquisition_queries += 1
        message = b"acquire:" + acquisition_queries.to_bytes(4, "big")
        signature = model.sign(message, h32(b"acquire-R" + message))
        md, tree, leaf = model.split_digest(model.digest(signature["R"], message))
        if (tree, leaf) == (source_tree, source_leaf):
            assert model.verify(message, signature)
            assert signature["ht"] == source["ht"]
            records.append({"message": message, "sig": signature,
                            "coords": model.forc_coords(md)})

    mixed_trial, mixed_R, mixed_message, mixed_coords, donors = \
        find_mixed_digest(model, records, source_tree, source_leaf)
    mixed = copy.deepcopy(source)
    mixed["R"] = mixed_R
    for i, donor_no in enumerate(donors):
        donor = records[donor_no]
        mixed["forc"][i] = copy.deepcopy(donor["sig"]["forc"][i])
        old_index, old_length = donor["coords"][i]
        new_index, new_length = mixed_coords[i]
        assert old_index == new_index and old_length <= new_length
        absolute = i * (1 << A) + old_index
        mixed["forc"][i]["node"] = model.forc_chain(
            mixed["forc"][i]["node"], source_tree, source_leaf,
            absolute, old_length, new_length - old_length)
    mixed_md, _, _ = model.split_digest(model.digest(mixed_R, mixed_message))
    assert model.forc_pk_from_sig(
        mixed["forc"], mixed_md, source_tree, source_leaf) == source_fpk
    assert model.verify(mixed_message, mixed)
    for record in records:
        whole = copy.deepcopy(record["sig"])
        whole["R"] = mixed_R
        assert not model.verify(mixed_message, whole)

    capacity = count_suffix(WOTS_W, WOTS_S)
    result = {
        "toy_parameters": {"n_bytes": N, "h": list(H), "a": A, "k": K,
                           "w_prime": W_PRIME, "wots_w": list(WOTS_W)},
        "wots_code_capacity_bits": capacity.bit_length() - 1,
        "source": {"tree": source_tree, "leaf": source_leaf,
                   "coords": source_coords},
        "forward_forgery": {"trials": trial, "coords": target_coords,
                            "accepted": True, "fresh_message": True},
        "coordinate_mixing_forgery": {
            "acquisition_queries": acquisition_queries,
            "retained_same_address_signatures": len(records),
            "grinding_trials": mixed_trial,
            "target_coords": mixed_coords,
            "donor_transcripts": donors,
            "no_single_transcript_covered_target": True,
            "accepted": True,
            "fresh_message": True,
        },
        "negative_controls": {
            "unadvanced_nodes_rejected": True,
            "backward_chain_attempt_rejected": True,
            "backward_search_trials": back_trial,
            "tampered_authentication_path_rejected": True,
            "wrong_complete_address_component_rejected": True,
            "cross_layer_splice_rejected": True,
        },
    }
    output = Path(__file__).with_name("toy_results.json")
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

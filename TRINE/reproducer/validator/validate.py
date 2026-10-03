#!/usr/bin/env python3
"""Offline semantic and checksum validation for the TRINE reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def text(rel: str) -> str:
    return (BASE / rel).read_text(encoding="utf-8")


def load(rel: str):
    return json.loads(text(rel))


def close(got: float, want: float, tol: float = 2e-5) -> None:
    assert math.isclose(got, want, rel_tol=0.0, abs_tol=tol), (got, want)


def validate_model(rel: str) -> None:
    by_name = {p["profile"]: p for p in load(rel)["profiles"]}
    expected = {
        "Balanced-I": (61.22652680549504, 75.83570554363702,
                       97.02914815975456, 91.10571203198053),
        "ShortSig-I": (62.99059219205809, 76.65237028983007,
                       97.01715518257092, 92.80291387556025),
    }
    assert set(by_name) == set(expected)
    for name, want in expected.items():
        row = by_name[name]
        ar = row["all_round_poisson_median"]
        cpu = row["fixed_index_weighted_total_cpu"]["full_cf_baseline"]
        close(ar["log2_signature_queries"], want[0])
        close(ar["log2_returned_signature_bits"], want[1])
        close(ar["log2_attacker_cycles_from_measured_decode_and_full_cf"], want[2])
        close(cpu["log2_total_cycles"], want[3])
        close(ar["probability"], 0.5)


def validate_jsonl(rel: str) -> None:
    rows = [json.loads(line) for line in text(rel).splitlines() if line.strip()]
    assert len(rows) == 2, rel
    for row in rows:
        assert row["reduced_seed_bits"] == 6
        assert row["pdf_signature_bytes"] in {3124, 1620}
        for flag in (
            "fresh_forgery_accepted", "wrong_message_rejected",
            "response_tamper_rejected", "digest_tamper_rejected",
            "secret_erased_before_forge", "drbg_explicitly_initialized",
        ):
            assert row[flag] is True, (rel, flag)


def validate_q64(rel: str) -> None:
    require(rel,
            "Q 18446744073709551615",
            "P 33932896019960893868",
            "prob 0.500000000000000000004451889380849",
            "log2_raw_table_bytes 70.4642808664133",
            "log2_attacker_cycles 94.2466267553992",
            "P 229826321259624867428",
            "prob 0.500000000000000000001155025813733",
            "log2_raw_table_bytes 73.2240684330762",
            "log2_attacker_cycles 96.9901880177406")


def validate_full_entropy(rel: str, profile: str, sig_bytes: int) -> None:
    require(rel,
            f"profile={profile}",
            "lambda_bits=128",
            "round_seed_bytes=16",
            f"signature_bytes={sig_bytes}",
            "verify=PASS",
            "open=PASS",
            "changed_message=REJECT")


def require(rel: str, *markers: str) -> None:
    body = text(rel)
    for marker in markers:
        assert marker in body, (rel, marker)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--check-latest", action="store_true")
args = parser.parse_args()

validate_model("results/frozen/resource-model.json")
validate_q64("results/frozen/fixed_q64_exact.txt")
validate_jsonl("results/frozen/native_balanced_results.jsonl")
validate_jsonl("results/frozen/native_shortsig_results.jsonl")
validate_full_entropy("results/frozen/full-entropy-balanced.txt",
                      "TRINE-Balanced-I", 3124)
validate_full_entropy("results/frozen/full-entropy-shortsig.txt",
                      "TRINE-ShortSig-I", 1620)
require("results/frozen/natural-collision-toy.txt",
        "sampling=independent_fresh_uniform",
        "witness_only_fresh_message_forgery=PASS", "overall=PASS")
require("results/frozen/shortsig-graph-toy.txt",
        "collision_graph_connected=PASS",
        "connected_witness_fresh_message_forgery=PASS", "overall=PASS")
require("results/frozen/partial_invariant_rerun.txt",
        "planted_equivariance_equal=64/64",
        "independent_control_equal=0/64", "speedup=9.102995")
require("results/frozen/seed_decode_benchmark.txt",
        "per_seed=0.345799062", "per_seed=0.342778750")

if args.check_latest:
    validate_model("results/latest/resource-model.json")
    validate_q64("results/latest/fixed_q64_exact.txt")
    validate_jsonl("results/latest/native-balanced.jsonl")
    validate_jsonl("results/latest/native-shortsig.jsonl")
    validate_full_entropy("results/latest/full-entropy-balanced.txt",
                          "TRINE-Balanced-I", 3124)
    validate_full_entropy("results/latest/full-entropy-shortsig.txt",
                          "TRINE-ShortSig-I", 1620)
    require("results/latest/portable-balanced.txt",
            "witness_only_fresh_message_forgery=PASS", "overall=PASS")
    require("results/latest/portable-shortsig.txt",
            "connected_witness_fresh_message_forgery=PASS", "overall=PASS")
    require("results/latest/partial-invariant.txt",
            "planted_equivariance_equal=64/64",
            "independent_control_equal=0/64")

require("README.md", "NIST PQC Forum, 21 February 2024",
        "not a physical `2^80` attack", "untouched salted source",
        "18,446,744,073,709,551,615")
require("SOURCE_SCOPE.md", "direct unsalted, message-independent PDF",
        "does not apply to the untouched submitted source")
require("patches/remove-source-only-salt.patch", "TRINE_salt_bytes",
        "round_index", "TRINE_SIG_BYTES")
require("src/pdf_full_entropy/params.h",
        "#define TRINE_round_seed_bytes TRINE_lambda_bytes",
        "#define TRINE_EXPECTED_SIG_BYTES 3124u",
        "#define TRINE_EXPECTED_SIG_BYTES 1620u")

private_root = b"/data" + b"/ngcc"
private_cache = b".cache" + b"/audit"
wrong_forum_name = b"PKC" + b" Forum"
for path in BASE.rglob("*"):
    rel_path = path.relative_to(BASE)
    if (not path.is_file() or
            rel_path.parts[:2] == ("results", "latest") or
            rel_path.parts[:1] == ("bin",)):
        continue
    if path.suffix in {".pyc", ".pyo"}:
        continue
    body = path.read_bytes()
    assert private_root not in body, path
    assert private_cache not in body, path
    assert wrong_forum_name not in body, path

manifest = BASE / "SHA256SUMS"
assert manifest.is_file()
for line in manifest.read_text().splitlines():
    expected, rel = line.split("  ", 1)
    path = BASE / rel
    assert path.is_file(), rel
    assert sha256(path) == expected, rel

print("semantic_validation=PASS")
print("ordinary_fresh_randomness_chain=PASS")
print("balanced_and_shortsig_fresh_forgery=PASS")
print("scope_and_prior_art_wording=PASS")

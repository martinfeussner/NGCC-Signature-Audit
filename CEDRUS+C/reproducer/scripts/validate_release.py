#!/usr/bin/env python3
"""Fail-closed validation for the CEDRUS+C release package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "expected"
LATEST = ROOT / "results" / "latest"
PAPER = ROOT.parent / "CEDRUS+C_Attack_Description.tex"
PDF = ROOT.parent / "CEDRUS+C_Attack_Description.pdf"


RESULT_NAMES = (
    "rigorous_complexity.json",
    "independent-bounds.json",
    "moment-check.json",
    "toy-strict-forge.json",
    "native-fors-splice-160f.json",
    "native-fors-splice-160s.json",
    "independent-audit.json",
)


def load(base: Path, name: str) -> dict:
    return json.loads((base / name).read_text())


def check_tree(base: Path) -> None:
    comp = load(base, "rigorous_complexity.json")
    direct = load(base, "independent-bounds.json")
    moments = load(base, "moment-check.json")
    toy = load(base, "toy-strict-forge.json")
    native_f = load(base, "native-fors-splice-160f.json")
    native_s = load(base, "native-fors-splice-160s.json")
    hostile = load(base, "independent-audit.json")

    f = comp["parameter_sets"]["CEDRUS+C-160f"]
    s = comp["parameter_sets"]["CEDRUS+C-160s"]
    assert f["parameters"]["h"] == 66
    assert f["parameters"]["a"] == 7 and f["parameters"]["k"] == 30
    assert s["parameters"]["h"] == 67
    assert s["parameters"]["a"] == 12 and s["parameters"]["k"] == 13

    for rowset in (f, s):
        for name in ("all_address_optimum", "memory_bounded_prefix_optimum"):
            row = rowset[name]
            assert row["poisson_mean_signing_queries_log2"] < 80
            assert row["expected_attacker_hmsg_calls_log2"] < 80
            assert row["success_lower_bound_before_query_cap_abort"] > 0.632
            assert row["poisson_numerics"]["omitted_tail_upper_bound_log2"] < -400
            assert row["poisson_numerics"]["second_moment_tail_incorporated"]

    fsoft = f["memory_bounded_prefix_optimum"]
    ssoft = s["memory_bounded_prefix_optimum"]
    assert fsoft["prefix_bits_retained"] == 6
    assert ssoft["prefix_bits_retained"] == 11
    assert fsoft["deterministic_fully_provisioned_table_bytes_log2"] < 80
    assert ssoft["deterministic_fully_provisioned_table_bytes_log2"] < 80
    assert fsoft["expected_returned_signature_bits_log2"] > 88
    assert ssoft["expected_returned_signature_bits_log2"] > 91
    assert fsoft["expected_honest_signer_reference_cycles_log2"] > 100
    assert ssoft["expected_honest_signer_reference_cycles_log2"] > 108
    assert f["exact_q_2^64"]["log2_mean_inverse_public_hmsg_trials"] > 160
    assert s["exact_q_2^64"]["log2_mean_inverse_public_hmsg_trials"] > 160

    assert direct["all_match"]
    assert all(row["candidate_values_match_to_1e_9"] for row in direct["checks"])
    assert moments["status"] == "PASS"
    assert toy["forgery"]["accepted_by_strict_verifier"]
    assert toy["forgery"]["fresh_message"] == "fresh-message-never-queried"
    assert toy["forgery"]["distinct_component_sources"] >= 2
    assert toy["forgery"]["target_vector_absent_from_ordinary_transcripts_at_address"]
    assert toy["forgery"]["whole_forged_transcript_absent_from_ordinary_transcripts"]
    assert all(toy["controls"].values())
    assert toy["scope"]["ordinary_randomized_signing_queries"]
    assert not toy["scope"]["fault_reset_or_repeated_randomness"]
    assert not toy["scope"]["index_collapse_bug"]
    assert not toy["scope"]["omitted_wots_membership"]

    for native, expected_set in (
        (native_f, "160-bit/30-trees/height-7"),
        (native_s, "160-bit/13-trees/height-12"),
    ):
        assert native["all_checks_pass"]
        assert native["parameter_set"] == expected_set
        assert native["coordinate_mixed_root_matches"]
        assert native["target_vector_absent_from_donors"]
        assert native["wrong_complete_address_changes_root"]
        assert native["mismatched_target_index_changes_root"]

    assert hostile["status"] == "CONFIRMED_ABSTRACT_ATTACK_NOT_HOST_SCALE"
    assert hostile["largest_closed_vs_direct_delta_bits"] < 1e-10
    assert hostile["largest_closed_vs_claim_delta_bits"] < 1e-10
    hf = hostile["actual_host_profiles"]["CEDRUS+C-160f"]
    hs = hostile["actual_host_profiles"]["CEDRUS+C-160s"]
    assert hf["actual_memtotal_bytes"] == 135_045_894_144
    assert hs["actual_memtotal_bytes"] == 135_045_894_144
    assert hf["minimum_hard_table_prefix_bits"] == 49
    assert hs["minimum_hard_table_prefix_bits"] == 54
    hf49 = hf["hard_ram_profiles_minimum_and_safer"]["49"]
    hs54 = hs["hard_ram_profiles_minimum_and_safer"]["54"]
    hs55 = hs["hard_ram_profiles_minimum_and_safer"]["55"]
    assert hf49["hard_table_fraction_of_memtotal"] < 0.7
    assert hs54["hard_table_fraction_of_memtotal"] < 0.9
    assert hf49["log2_total_interactions"] < 80
    assert hs54["log2_total_interactions"] < 80
    assert hs55["log2_total_interactions"] > 80
    assert hf49["ideal_64_core_2GHz_signing_wall_years"] > 1e12
    assert hs54["ideal_64_core_2GHz_signing_wall_years"] > 1e15


def check_release_text() -> None:
    text = PAPER.read_text()
    flat = " ".join(text.split())
    required = (
        "ordinary independently randomized signatures",
        "strict repaired verifier",
        "concrete parameter analysis is limited to the two category-I sets",
        "No full-parameter end-to-end attack was executed",
        "does not use reset",
        "minimum support requirement, not a maximum per-key lifetime",
        "specification states no per-key lifetime cap",
        "parameter/lifetime-policy issue under the NGCC",
        r"\bibitem{ngcc-requirements}",
        "not a machine-practical computation",
        "OpenAI Codex using Daybreak Blue at Ultra reasoning effort",
        "The computations were performed on the Norwegian Research and Education Cloud",
        "using resources provided by the University of Bergen and the University",
        "of Oslo.",
    )
    for phrase in required:
        assert phrase in flat, phrase
    assert PDF.stat().st_size > 100_000
    assert PDF.read_bytes().startswith(b"%PDF-")
    for name in (
        "ATTACK_LEDGER.md",
        "HOSTILE_AUDIT.md",
        "INDEPENDENT_HOSTILE_REVIEW.md",
        "SOURCE_CONFORMANCE.md",
        "PERFORMANCE_SOURCE.md",
        "perf_x86_1.md",
        "lifetime-scan.json",
        "prior-art-check.md",
    ):
        assert (ROOT / "evidence" / name).stat().st_size > 500
    for name in (
        "README.md",
        "spec-repair.patch",
        "spec-repair-hashes.json",
        "verify_core.c",
        "verify_core.h",
    ):
        base = ROOT if name == "README.md" else ROOT / "patches"
        assert (base / name).stat().st_size > 100
    public_text = [PAPER, ROOT / "README.md",
                   *sorted((ROOT / "evidence").iterdir()),
                   ROOT / "patches" / "README.md"]
    for path in public_text:
        if path.is_file():
            blob = path.read_text(errors="replace")
            for marker in ("/" + "data/ngcc/", "." + "cache/audit/"):
                assert marker not in blob, path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen-only", action="store_true")
    args = parser.parse_args()

    assert all((EXPECTED / name).is_file() for name in RESULT_NAMES)
    check_tree(EXPECTED)
    if not args.frozen_only:
        assert all((LATEST / name).is_file() for name in RESULT_NAMES)
        check_tree(LATEST)
        for name in RESULT_NAMES:
            assert (LATEST / name).read_bytes() == (EXPECTED / name).read_bytes(), name
    check_release_text()

    result = {
        "status": "PASS",
        "checks": {
            "strict_repaired_verifier_scope": True,
            "ordinary_randomized_acquisition": True,
            "scaled_fresh_message_forgery": True,
            "negative_controls": True,
            "native_full_parameter_fors_splice_160f_160s": True,
            "exact_and_independent_probability_bounds": True,
            "all_address_and_soft_2_80_rows": True,
            "host_ram_rows": True,
            "physical_infeasibility_accounted": True,
            "query_lifetime_qualification": True,
            "manuscript_scope_and_provenance": True,
        },
    }
    if not args.frozen_only:
        (LATEST / "validation.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

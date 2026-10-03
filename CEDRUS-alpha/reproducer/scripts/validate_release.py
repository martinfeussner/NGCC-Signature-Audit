#!/usr/bin/env python3
"""Validate the release outputs and all verdict-critical invariants."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def close(x: float, y: float, tol: float = 2e-3) -> None:
    assert abs(x-y) <= tol, (x,y)


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--work",type=Path,required=True)
    args=ap.parse_args()
    complexity=json.loads((args.work/"hostile_complexity.json").read_text())
    toy=json.loads((args.work/"toy_spec_results.json").read_text())
    full_toy=json.loads((args.work/"toy_results.json").read_text())
    full_parameter=json.loads((args.work/"full_parameter_forc_splice.json").read_text())
    native=json.loads((args.work/"native_results.json").read_text())
    repair=json.loads((args.work/"spec_repair_replay.json").read_text())

    assert set(complexity["sets"]) == {
        "160s","160f","256s","256f","384s","384f","512s","512f"
    }
    for item in complexity["sets"].values():
        rigorous=item["rigorous_hmsg_work_optimized"]
        assert rigorous["poisson_query_mean_log2"] < 80
        assert rigorous["attacker_acquisition_hmsg_calls_log2"] == \
            rigorous["poisson_query_mean_log2"]
        close(rigorous["attacker_total_hmsg_calls_log2"],
              rigorous["optimized_metric_log2"],1e-12)
        assert rigorous["optimized_metric_log2"] < 80
        assert rigorous["table_lower_tail_chebyshev_log2"] < -45
        assert rigorous["unconditional_success_lower_bound"] > 0.632
        assert rigorous["returned_signature_bytes_log2"] \
            > rigorous["optimized_metric_log2"]
        assert rigorous["second_moment_tail_incorporated"] is True
        assert rigorous["second_moment_upper_bound_log2"] >= \
            rigorous["truncated_second_moment_log2"]
        assert rigorous["second_moment_upper_bound_log2"] >= \
            rigorous["omitted_occupancy_tail_log2"]

    physical=[x["rigorous_hmsg_work_optimized"]
              for x in complexity["sets"].values()]
    close(max(x["poisson_query_mean_log2"] for x in physical),77.520)
    close(max(x["candidate_trials_63pct_given_good_table_log2"]
              for x in physical),72.367205973)
    close(max(x["returned_signature_bits_log2"] for x in physical),97.101200582)
    close(max(x["full_auth_table_bytes_log2"] for x in physical),92.397588936)
    close(max(x["record_updates_log2"] for x in physical),83.074588852)
    close(max(x["honest_signer_hashes_log2"] for x in physical),100.851559237)

    s160=complexity["sets"]["160f"]["rigorous_hmsg_work_optimized"]
    close(s160["poisson_query_mean_log2"],71.165)
    close(s160["candidate_trials_63pct_given_good_table_log2"],66.8784475)
    close(s160["optimized_metric_log2"],71.2370937)
    close(s160["returned_signature_bytes_log2"],85.4102556)
    close(s160["honest_signer_hashes_log2"],88.7674886)

    fixed=complexity["160f_detailed"]["fixed_address"]
    assert fixed["retained_exact_address_hits"] == 554
    hp=fixed["high_probability_acquisition"]
    close(hp["signing_queries_log2"],76.113742166049)
    close(hp["fixed_public_hmsg_trials_log2"],72.445407801058)
    close(hp["attacker_total_hmsg_calls_log2"],76.222974454677)
    close(hp["returned_signature_bytes_log2"],90.358997746356)
    close(hp["honest_signer_hashes_log2"],93.716230816013)

    shard=complexity["160f_detailed"]["six_bit_prefix_full_path_table"]
    close(shard["poisson_query_mean_log2"],71.458,3e-3)
    close(shard["candidate_trials_63pct_given_good_table_log2"],67.160125,3e-3)
    close(shard["optimized_metric_log2"],71.529544,3e-3)
    close(shard["full_auth_table_bytes_log2"],77.478716,3e-3)
    close(shard["hard_full_auth_table_bytes_log2"],79.1751402)
    assert shard["hard_full_auth_table_bytes_log2"] < 80
    assert shard["table_lower_tail_chebyshev_log2"] < -48
    p=complexity["sets"]["160f"]["parameters"]
    record=(p["a"]+1)*p["n"]+1
    suffix=(p["d"]*p["olen"]+p["h"])*p["n"]+16
    hard=(1 << (p["h"]-6))*(p["k"]*(1 << p["a"])*record+suffix)
    close(math.log2(hard),shard["hard_full_auth_table_bytes_log2"],1e-12)

    assert toy["forgery_accepted"]
    assert toy["target_was_never_queried"]
    assert toy["ordinary_hedged_signing_queries"] > 0
    assert toy["donor_count_distinct"] >= 2
    assert all(toy["negative_controls"].values())

    mix=full_toy["coordinate_mixing_forgery"]
    assert full_toy["forward_forgery"]["accepted"]
    assert full_toy["forward_forgery"]["fresh_message"]
    assert mix["accepted"] and mix["fresh_message"]
    assert mix["no_single_transcript_covered_target"]
    assert len(set(mix["donor_transcripts"])) >= 2
    assert all(full_toy["negative_controls"].values())

    assert full_parameter["all_eight_parameter_sets_pass"]
    assert set(full_parameter["sets"]) == {
        "160s","160f","256s","256f","384s","384f","512s","512f"
    }
    for name,item in full_parameter["sets"].items():
        p=item["parameters"]
        assert item["ordering_relation_identical"] is True
        assert item["status"] == "PASS"
        for convention in ("algorithm_14_18_endpoint","prose_shifted_endpoint"):
            result=item[convention]
            assert result["mixed_pk_matches"] is True
            assert result["coordinate_count"] == p["k"]
            assert result["coordinate_donors_used"] == 3
            assert result["forc_signature_bytes"] == p["k"]*(p["a"]+1)*p["n"]
            assert all(result["negative_controls"].values()), (name,convention)
        assert item["algorithm_14_18_endpoint"]["chain_endpoint_position"] == p["w_prime"]
        assert item["prose_shifted_endpoint"]["chain_endpoint_position"] == p["w_prime"]-1

    assert native["all_checks_pass"]
    assert all(native.values())
    assert repair["status"] == "PASS"
    assert repair["observed_pristine_crlf"] is True
    assert repair["observed_pristine_thash_missing_final_newline"] is True
    assert repair["repaired_tree_sha256"] == repair["replayed_tree_sha256"]

    audit=(Path(__file__).resolve().parent.parent/"evidence"/
           "SPEC_LIFETIME_COUNTER_AUDIT.md").read_text()
    assert "does **not** specify a maximum number of" in audit
    assert "does **not** contain a complete counter-pruning mechanism" in audit
    assert "Section 3.2" in audit and "q_sig" in audit
    assert "Algorithm 20, PDF p.35, line 16" in audit

    release_root=Path(__file__).resolve().parent.parent
    forbidden=("/data"+"/ngcc", ".cache"+"/audit", "/home"+"/ubuntu")
    for path in sorted(release_root.rglob("*")):
        rel=path.relative_to(release_root)
        if not path.is_file() or rel.parts[0] in {"work","build"}:
            continue
        try:
            text=path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in forbidden:
            assert marker not in text, (rel.as_posix(),marker)

    result={
        "all_eight_parameter_sets_below_2^80_attacker_hmsg_calls":True,
        "all_negative_controls_rejected":True,
        "hostile_review_sha256":"32b915adafae79c53cf2a808f97fa8bc17b2af0ab1bf67a884efc44de08bc4de",
        "native_256f_conformance_checks_pass":True,
        "full_parameter_forc_splice_all_eight_sets_pass":True,
        "pristine_source_patch_replay_pass":True,
        "packaged_text_has_no_host_paths":True,
        "submission_lifetime_and_counter_audit_present":True,
        "ordinary_fresh_message_reduced_forgery":True,
        "whole_transcript_noncoverage_control":True,
        "six_bit_shard_hard_table_below_2^80_bytes":True,
        "verdict":"PASS_WITH_MANDATORY_NARROWING",
    }
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__ == "__main__":
    main()

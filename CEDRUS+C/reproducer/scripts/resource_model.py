#!/usr/bin/env python3
"""Rigorous ideal-HMSG resource bounds for CEDRUS+C FORS accumulation.

The acquisition count is deliberately Poissonized.  Consequently the loads
of all complete bottom addresses are *independent* Poisson variables; no
binomial-to-Poisson approximation is used.  The adversary aborts before a
hard 2^80 signing-query cap.  Numerical Poisson sums are truncated only after
an explicit Chernoff upper bound on the omitted tail is below 2^-400.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from pathlib import Path


@dataclass(frozen=True)
class Params:
    name: str
    n: int
    h: int
    d: int
    heights: tuple[int, ...]
    a: int
    k: int
    a_prime: int
    wots_len: int
    wots_widths: tuple[int, ...]
    wots_valid_probability: float
    signature_bytes: int
    measured_sign_cycles: float
    measured_hmsg_tsc_ticks: float


SETS = (
    Params(
        "CEDRUS+C-160s", 20, 67, 9, (8, 8, 8, 8, 7, 7, 7, 7, 7),
        12, 13, 15, 26, (32, 32) + (64,) * 24,
        6.77606121308699e-5, 9460, 8.65e9, 2917.959,
    ),
    Params(
        "CEDRUS+C-160f", 20, 66, 17, (4,) * 15 + (3, 3),
        7, 30, 9, 40, (8, 8) + (16,) * 38,
        0.003473580913518225, 19812, 513.49e6, 5988.144,
    ),
)


def logadd2(a: float, b: float) -> float:
    if a == -math.inf:
        return b
    if b == -math.inf:
        return a
    m = max(a, b)
    return m + math.log2(2.0 ** (a - m) + 2.0 ** (b - m))


def logsub2(a: float, b: float) -> float:
    """Return log2(2^a-2^b), requiring a>b."""
    assert a > b
    return a + math.log2(1.0 - 2.0 ** (b - a))


def coverage_moments_given_r(r: int, p: Params) -> tuple[float, float]:
    """E[Z|r] and E[Z^2|r] for one address's covered-vector fraction Z."""
    if r == 0:
        return 0.0, 0.0
    B = 1 << p.a
    q1r = math.exp(r * math.log1p(-1.0 / B))
    g = 1.0 - q1r
    q2r = math.exp(r * math.log1p(-2.0 / B)) if B > 2 else 0.0
    two_seen = 1.0 - 2.0 * q1r + q2r
    second_coordinate = g / B + (1.0 - 1.0 / B) * two_seen
    # Roundoff can make the occupancy identity miss its natural range by ulps.
    second_coordinate = min(1.0, max(g * g, second_coordinate))
    return g ** p.k, second_coordinate ** p.k


def poisson_upper_tail_log2(lam: float, first_omitted: int) -> float:
    """Chernoff upper bound Pr[Pois(lam)>=first_omitted]."""
    u = float(first_omitted)
    if u <= lam:
        return 0.0
    return (-lam + u * (1.0 + math.log(lam / u))) / math.log(2.0)


def poisson_moments(qbits: float, p: Params) -> dict:
    lam = 2.0 ** (qbits - p.h)
    cutoff = max(128, int(math.ceil(lam + 40.0 * math.sqrt(lam + 1.0) + 200.0)))
    lmu = -math.inf
    lnu = -math.inf
    log_lam = math.log(lam)
    for r in range(1, cutoff + 1):
        lp = (-lam + r * log_lam - math.lgamma(r + 1.0)) / math.log(2.0)
        m1, m2 = coverage_moments_given_r(r, p)
        if m1:
            lmu = logadd2(lmu, lp + math.log2(m1))
        if m2:
            lnu = logadd2(lnu, lp + math.log2(m2))
    tail = poisson_upper_tail_log2(lam, cutoff + 1)
    if tail > -400.0:
        raise ArithmeticError(f"Poisson tail too large: 2^{tail}")
    # Since Z^2 <= 1, the same Poisson tail is an additive upper bound on the
    # omitted second-moment contribution.  Keep the truncated value visible,
    # but use the upper bound in every concentration calculation.
    lnu_upper = logadd2(lnu, tail)
    return {
        "lambda": lam,
        "log2_mu": lmu,
        "log2_nu_truncated": lnu,
        "log2_nu_upper": lnu_upper,
        "second_moment_tail_incorporated": True,
        "cutoff": cutoff,
        "omitted_tail_upper_bound_log2": tail,
    }


def signer_calls(p: Params) -> dict:
    total_steps = sum(w - 1 for w in p.wots_widths)
    fixed_sum = total_steps // 2
    wots_pkgen = p.wots_len + total_steps + 1
    outer_hmsg = float(1 << p.a_prime)
    fors_sign = p.k + p.k * (3 * (1 << p.a) - p.a - 3)
    fors_reconstruct = p.k * (p.a + 1) + 1
    xmss_auth = sum((wots_pkgen + 1) * ((1 << height) - 1) - height
                    for height in p.heights)
    wots_sign = p.d * (1.0 / p.wots_valid_probability + fixed_sum + p.wots_len)
    lower_reconstruct = sum(1 + (total_steps - fixed_sum) + 1 + height
                            for height in p.heights[:-1])
    total = (1 + outer_hmsg + fors_sign + fors_reconstruct + xmss_auth
             + wots_sign + lower_reconstruct)
    return {
        "wots_total_steps": total_steps,
        "wots_fixed_sum": fixed_sum,
        "wots_expected_counter_trials": 1.0 / p.wots_valid_probability,
        "prfmsg": 1,
        "outer_hmsg": outer_hmsg,
        "fors_sign": fors_sign,
        "fors_reconstruct": fors_reconstruct,
        "xmss_auth": xmss_auth,
        "wots_sign": wots_sign,
        "lower_root_reconstruct": lower_reconstruct,
        "expected_hash_family_calls_per_signature": total,
        "log2_expected_hash_family_calls_per_signature": math.log2(total),
        "measured_reference_cycles_per_signature": p.measured_sign_cycles,
        "log2_measured_reference_cycles_per_signature": math.log2(p.measured_sign_cycles),
    }


def suffix_bytes(p: Params) -> int:
    # Each XMSS layer serializes a 4-byte WOTS counter, len n-byte WOTS nodes,
    # and its authentication path.  Across layers the path heights sum to h.
    return p.d * (4 + p.wots_len * p.n) + p.h * p.n


def table_costs(qbits: float, p: Params, prefix_bits: int) -> dict:
    lam = 2.0 ** (qbits - p.h)
    B = 1 << p.a
    retained_addresses = 2.0 ** (p.h - prefix_bits)
    occupied = -math.expm1(-lam)
    distinct = B * (-math.expm1(-lam / B))
    frontier = 0.0
    for j in range(p.a):
        size = 1 << j
        frontier += (B / size) * (
            math.exp(-lam * size / B) - math.exp(-lam * 2 * size / B)
        )
    suffix = suffix_bytes(p)
    component_record = (p.a + 1) * p.n + 1
    expected_full = retained_addresses * (
        p.k * distinct * component_record + occupied * (suffix + 16)
    )
    # Compact forest: one n-byte secret per disclosed leaf, one n-byte
    # frontier node, and a direct B-bit presence bitmap for every coordinate
    # of every occupied retained address.
    expected_compact = retained_addresses * (
        p.k * p.n * (distinct + frontier)
        + occupied * (p.k * B / 8.0 + suffix + 16)
    )
    hard_full = (1 << (p.h - prefix_bits)) * (
        p.k * B * component_record + suffix + 16
    )
    return {
        "expected_occupied_address_fraction": occupied,
        "expected_distinct_leaves_per_coordinate": distinct,
        "expected_frontier_nodes_per_coordinate": frontier,
        "component_record_bytes": component_record,
        "hypertree_suffix_plus_metadata_bytes": suffix + 16,
        "expected_complete_path_table_bytes_log2": math.log2(expected_full),
        "expected_compact_forest_table_bytes_log2": math.log2(expected_compact),
        "deterministic_fully_provisioned_table_bytes_log2": math.log2(hard_full),
    }


def cap_abort_log2(qbits: float) -> float:
    """Chernoff bound for Pois(2^qbits) reaching the hard cap 2^80."""
    mu = 2.0 ** qbits
    cap = 2.0 ** 80
    if mu >= cap:
        return 0.0
    return (-mu + cap * (1.0 + math.log(mu / cap))) / math.log(2.0)


def all_address_profile(p: Params, qbits: float, prefix_bits: int) -> dict:
    mom = poisson_moments(qbits, p)
    lmu, lnu = mom["log2_mu"], mom["log2_nu_upper"]
    mean_trial = -p.a_prime - prefix_bits + lmu
    # Use twice the inverse mean.  On a table with >= half its mean success
    # mass this gives failure at most e^-1.
    tbits = 1.0 - mean_trial
    relvar_upper = lnu + prefix_bits - p.h - 2.0 * lmu
    cheb_bad_log2 = 2.0 + relvar_upper
    cheb_bad = min(1.0, 2.0 ** cheb_bad_log2)
    one_run = (1.0 - cheb_bad) * (1.0 - math.exp(-1.0))
    calls = signer_calls(p)
    interaction = logadd2(qbits, tbits)
    hmsg_calls = interaction  # one to parse each signature plus one per trial
    worst_table_ops = interaction + math.log2(p.k)
    abort_log2 = cap_abort_log2(qbits)
    row = {
        "prefix_bits_retained": prefix_bits,
        "poisson_mean_signing_queries_log2": qbits,
        "hard_signing_query_cap_log2": 80,
        "query_cap_abort_probability_upper_bound_log2": abort_log2,
        "query_cap_abort_bound_negative_exponent_log2": (
            math.log2(-abort_log2) if abort_log2 < 0 else None
        ),
        "mean_address_occupancy": mom["lambda"],
        "mean_covered_vector_fraction_log2": lmu,
        "second_moment_covered_vector_fraction_log2": lnu,
        "mean_public_trial_success_log2": mean_trial,
        "mean_inverse_public_hmsg_trials_log2": -mean_trial,
        "fixed_public_hmsg_trials_log2": tbits,
        "expected_total_oracle_interactions_log2": interaction,
        "expected_attacker_hmsg_calls_log2": hmsg_calls,
        "calibrated_attacker_hmsg_tsc_ticks_log2": (
            hmsg_calls + math.log2(p.measured_hmsg_tsc_ticks)
        ),
        "calibrated_attacker_hmsg_input_bytes_log2": hmsg_calls + math.log2(96),
        "worst_case_logical_table_updates_and_probes_log2": worst_table_ops,
        "table_half_mean_failure_chebyshev_log2": cheb_bad_log2,
        "success_lower_bound_before_query_cap_abort": one_run,
        "expected_returned_signature_bytes_log2": qbits + math.log2(p.signature_bytes),
        "expected_returned_signature_bits_log2": qbits + math.log2(p.signature_bytes) + 3.0,
        "hard_cap_returned_signature_bytes_log2": 80.0 + math.log2(p.signature_bytes),
        "expected_honest_signer_hash_calls_log2": (
            qbits + calls["log2_expected_hash_family_calls_per_signature"]
        ),
        "expected_honest_signer_reference_cycles_log2": (
            qbits + calls["log2_measured_reference_cycles_per_signature"]
        ),
        "poisson_numerics": mom,
    }
    row.update(table_costs(qbits, p, prefix_bits))
    return row


def optimize_all(p: Params, prefix_bits: int) -> dict:
    def score(q: float) -> tuple[float, dict]:
        row = all_address_profile(p, q, prefix_bits)
        return row["expected_total_oracle_interactions_log2"], row

    # Coarse then millibit scan.  The relevant minima are smooth and unique.
    best = None
    q = float(p.h)
    while q <= 79.0 + 1e-12:
        s, row = score(q)
        if best is None or s < best[0]:
            best = (s, q, row)
        q += 0.05
    assert best is not None
    center = best[1]
    for i in range(-100, 101):
        q = center + i * 0.001
        if q < p.h or q > 79:
            continue
        s, row = score(q)
        if s < best[0]:
            best = (s, q, row)
    row = best[2]
    row["optimization_metric"] = "expected signing queries + fixed public HMSG trials"
    row["optimization_grid_resolution_bits"] = 0.001
    return row


def optimize_physical(p: Params, prefix_bits: int) -> dict:
    """Minimize the largest displayed attacker-side physical exponent.

    Bytes and calibrated TSC ticks are deliberately kept as separate units in
    the returned row.  The mixed maximum is only a reproducible way to choose
    a Pareto point; it is not called a single operation count.
    """
    def objective(row: dict) -> float:
        return max(
            row["expected_returned_signature_bytes_log2"],
            row["calibrated_attacker_hmsg_tsc_ticks_log2"],
            row["expected_complete_path_table_bytes_log2"],
            row["deterministic_fully_provisioned_table_bytes_log2"],
        )

    best = None
    q = float(p.h)
    while q <= 79.0 + 1e-12:
        row = all_address_profile(p, q, prefix_bits)
        score = objective(row)
        if best is None or score < best[0]:
            best = (score, q, row)
        q += 0.05
    assert best is not None
    center = best[1]
    for i in range(-100, 101):
        q = center + i * 0.001
        if q < p.h or q > 79:
            continue
        row = all_address_profile(p, q, prefix_bits)
        score = objective(row)
        if score < best[0]:
            best = (score, q, row)
    row = best[2]
    row["selection_metric"] = (
        "minimize max(returned bytes, calibrated HMSG TSC ticks, expected table bytes, hard table bytes)"
    )
    row["selection_metric_exponent"] = best[0]
    return row


def exact_binomial_coverage_q64(p: Params) -> dict:
    """Exact Bin(2^64,2^-h) mixture by high-precision recurrence."""
    q = 1 << 64
    N = 1 << p.h
    B = 1 << p.a
    with localcontext() as ctx:
        ctx.prec = 160
        one = Decimal(1)
        prob = (one - one / Decimal(N)) ** q
        total = Decimal(0)
        for r in range(0, 161):
            if r:
                g = one - (one - one / Decimal(B)) ** r
                total += prob * (g ** p.k)
            prob = (prob * Decimal(q - r) / Decimal(r + 1)
                    / Decimal(N - 1))
        log2_cov = float(total.ln() / Decimal(2).ln())
    return {
        "fixed_signing_queries_log2": 64,
        "log2_exact_binomial_covered_vector_fraction": log2_cov,
        "log2_mean_inverse_public_hmsg_trials": p.a_prime - log2_cov,
        "log2_rigorous_half_mean_public_hmsg_budget": p.a_prime - log2_cov + 1,
        "summation_last_occupancy": 160,
    }


def fixed_address_profile(p: Params, r: int, theta: float = 0.5) -> dict:
    m1, m2 = coverage_moments_given_r(r, p)
    qbits = p.h + math.log2(r)
    tbits = p.a_prime + p.h - math.log2(theta * m1)
    interaction = logadd2(qbits, tbits)
    pz = (1.0 - theta) ** 2 * m1 * m1 / m2
    cap_mean_hits = 2.0 ** (80 - p.h)
    if r < cap_mean_hits:
        delta = 1.0 - r / cap_mean_hits
        cap_fail_log2 = -cap_mean_hits * delta * delta / (2.0 * math.log(2.0))
        reach_lb = 1.0 - (0.0 if cap_fail_log2 < -1074 else 2.0 ** cap_fail_log2)
    else:
        cap_fail_log2 = 0.0
        reach_lb = 0.0
    table = table_costs(qbits, p, p.h)  # one retained address
    calls = signer_calls(p)
    return {
        "retained_exact_address_hits": r,
        "paley_zygmund_theta": theta,
        "expected_signing_queries_log2": qbits,
        "hard_signing_query_cap_log2": 80,
        "cap_mean_hits_at_target_address": cap_mean_hits,
        "failure_to_reach_r_hits_by_cap_chernoff_log2": cap_fail_log2,
        "reach_r_hits_probability_lower_bound": reach_lb,
        "mean_covered_vector_fraction_log2": math.log2(m1),
        "second_moment_covered_vector_fraction_log2": math.log2(m2),
        "paley_zygmund_good_table_probability": pz,
        "fixed_public_hmsg_trials_log2": tbits,
        "expected_total_oracle_interactions_log2": interaction,
        "one_run_success_lower_bound": reach_lb * pz * (1.0 - math.exp(-1.0)),
        "expected_returned_signature_bytes_log2": qbits + math.log2(p.signature_bytes),
        "hard_cap_returned_signature_bytes_log2": 80.0 + math.log2(p.signature_bytes),
        "expected_attacker_hmsg_calls_log2": interaction,
        "calibrated_attacker_hmsg_tsc_ticks_log2": (
            interaction + math.log2(p.measured_hmsg_tsc_ticks)
        ),
        "calibrated_attacker_hmsg_input_bytes_log2": interaction + math.log2(96),
        "worst_case_logical_table_updates_and_probes_log2": interaction + math.log2(p.k),
        "expected_honest_signer_hash_calls_log2": (
            qbits + calls["log2_expected_hash_family_calls_per_signature"]
        ),
        "expected_honest_signer_reference_cycles_log2": (
            qbits + calls["log2_measured_reference_cycles_per_signature"]
        ),
        **table,
    }


def optimize_fixed_address(p: Params) -> dict:
    cap_mean_hits = int(2 ** (80 - p.h))
    best = None
    # Restrict to r <= 7/8 of the cap mean.  This preserves a concrete,
    # overwhelmingly likely stopping guarantee rather than optimizing an
    # expectation whose mass lies beyond the allowed signing-query cap.
    for r in range(1, (7 * cap_mean_hits) // 8 + 1):
        row = fixed_address_profile(p, r)
        score = row["expected_total_oracle_interactions_log2"]
        if best is None or score < best[0]:
            best = (score, row)
    assert best is not None
    best[1]["optimization_constraint"] = (
        "r <= 7/8 of expected target-address hits under the 2^80 query cap"
    )
    return best[1]


def amplify_fixed_address(p: Params, base: dict, repetitions: int) -> dict:
    """Independent repetitions, each on a distinct preselected full address."""
    assert repetitions >= 1
    add = math.log2(repetitions)
    r = base["retained_exact_address_hits"]
    total_cap = 1 << 80
    subcap = total_cap // repetitions
    subcap_bits = math.log2(subcap)
    mean_hits = subcap / float(1 << p.h)
    if r >= mean_hits:
        raise ValueError("per-repetition cap cannot reach retained hit target")
    delta = 1.0 - r / mean_hits
    cap_fail_log2 = -mean_hits * delta * delta / (2.0 * math.log(2.0))
    cap_fail = 0.0 if cap_fail_log2 < -1074 else 2.0 ** cap_fail_log2
    per_success = ((1.0 - cap_fail)
                   * base["paley_zygmund_good_table_probability"]
                   * (1.0 - math.exp(-1.0)))
    return {
        "independent_repetitions": repetitions,
        "distinct_preselected_addresses": repetitions,
        "retained_exact_address_hits_per_repetition": r,
        "hard_signing_query_cap_total_log2": 80,
        "hard_signing_query_subcap_per_repetition": subcap,
        "hard_signing_query_subcap_per_repetition_log2": subcap_bits,
        "expected_signing_queries_total_log2": base["expected_signing_queries_log2"] + add,
        "fixed_public_hmsg_trials_total_log2": base["fixed_public_hmsg_trials_log2"] + add,
        "expected_total_oracle_interactions_log2": (
            base["expected_total_oracle_interactions_log2"] + add
        ),
        "expected_returned_signature_bytes_log2": (
            base["expected_returned_signature_bytes_log2"] + add
        ),
        "expected_attacker_hmsg_calls_log2": (
            base["expected_attacker_hmsg_calls_log2"] + add
        ),
        "calibrated_attacker_hmsg_tsc_ticks_log2": (
            base["calibrated_attacker_hmsg_tsc_ticks_log2"] + add
        ),
        "expected_honest_signer_hash_calls_log2": (
            base["expected_honest_signer_hash_calls_log2"] + add
        ),
        "expected_honest_signer_reference_cycles_log2": (
            base["expected_honest_signer_reference_cycles_log2"] + add
        ),
        "expected_complete_path_table_bytes_log2": (
            base["expected_complete_path_table_bytes_log2"] + add
        ),
        "deterministic_fully_provisioned_table_bytes_log2": (
            base["deterministic_fully_provisioned_table_bytes_log2"] + add
        ),
        "per_repetition_cap_failure_chernoff_log2": cap_fail_log2,
        "per_repetition_success_lower_bound": per_success,
        "amplified_success_lower_bound": 1.0 - (1.0 - per_success) ** repetitions,
    }


def main() -> None:
    output = {
        "model": {
            "acquisition": (
                "Poisson(mean=2^q) ordinary randomized signing queries, abort before 2^80; "
                "complete-address occupancies are exactly independent Poisson variables"
            ),
            "target": (
                "fresh never-queried message; public R,counter enumeration; fixed T=2/mean "
                "gives >=1-e^-1 success when realized table mass >= half its mean"
            ),
            "idealization": "independent random-oracle HMSG fields after rejection",
            "numerical_tail": "explicit Poisson Chernoff bound below 2^-400",
        },
        "parameter_sets": {},
    }
    for p in SETS:
        min_prefix = math.ceil(
            math.log2(
                (1 << p.h) * (
                    p.k * (1 << p.a) * ((p.a + 1) * p.n + 1)
                    + suffix_bytes(p) + 16
                )
            ) - 80.0
        )
        fixed = optimize_fixed_address(p)
        rows = {
            "parameters": {**asdict(p), "heights": list(p.heights),
                           "wots_widths": list(p.wots_widths)},
            "hypertree_suffix_bytes": suffix_bytes(p),
            "signer_accounting": signer_calls(p),
            "all_address_optimum": optimize_all(p, 0),
            "hard_table_below_2^80_prefix_bits": min_prefix,
            "memory_bounded_prefix_optimum": optimize_all(p, min_prefix),
            "memory_bounded_physical_pareto_point": optimize_physical(p, min_prefix),
            "fixed_complete_address_optimum": fixed,
            "exact_q_2^64": exact_binomial_coverage_q64(p),
            "prefix_tradeoffs": {
                str(b): optimize_all(p, b)
                for b in sorted({0, 2, 4, 6, 8, min_prefix}) if b <= p.h
            },
            "fixed_query_rows": {
                str(q): all_address_profile(p, float(q), min_prefix)
                for q in (64, 70, 72, 74, 76, 78, 79)
            },
        }
        if p.name == "CEDRUS+C-160f":
            rows["sixfold_fixed_complete_address_attack"] = amplify_fixed_address(
                p, fixed, 6
            )
        output["parameter_sets"][p.name] = rows

    path = Path(__file__).resolve().parent.parent / "results" / "latest" / "rigorous_complexity.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

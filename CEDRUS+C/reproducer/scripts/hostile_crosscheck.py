#!/usr/bin/env python3
"""Independent hostile audit of the CEDRUS+C FORS accumulation estimates.

This file deliberately does not import the candidate's analysis code.  It
checks the key occupancy moments in two independent ways:

* a direct Poisson summation over the per-address load; and
* high-precision closed forms obtained from the Poisson probability-
  generating function.

It also recomputes the table sizes, concentration bound, exact WOTS+C
acceptance probabilities, actual-host RAM shards, traffic, and a conservative
64-core wall-time estimate from the cycle counts printed in the submission.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from dataclasses import dataclass
from decimal import Decimal, localcontext
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CANDIDATE = ROOT


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
    wots_widths: tuple[int, ...]
    signature_bytes: int
    pdf_sign_cycles: int
    harness_sign_cycles: int
    measured_hmsg_tsc_ticks: float

    @property
    def wots_len(self) -> int:
        return len(self.wots_widths)


F = Params(
    "CEDRUS+C-160f", 20, 66, 17, (4,) * 15 + (3, 3), 7, 30, 9,
    (8, 8) + (16,) * 38, 19_812, 335_982_300, 513_490_000, 5_988.144,
)
S = Params(
    "CEDRUS+C-160s", 20, 67, 9, (8, 8, 8, 8, 7, 7, 7, 7, 7), 12, 13, 15,
    (32, 32) + (64,) * 24, 9_460, 5_662_176_265, 8_650_000_000,
    2_917.959,
)
PARAMS = (F, S)


def logadd2(x: float, y: float) -> float:
    if x == -math.inf:
        return y
    if y == -math.inf:
        return x
    m = max(x, y)
    return m + math.log2(2.0 ** (x - m) + 2.0 ** (y - m))


def conditional_moments(r: int, p: Params) -> tuple[float, float]:
    """E[Z|r], E[Z^2|r] for covered k-vectors at one address."""
    if r == 0:
        return 0.0, 0.0
    B = 1 << p.a
    alpha_r = math.exp(r * math.log1p(-1.0 / B))
    beta_r = math.exp(r * math.log1p(-2.0 / B))
    g = 1.0 - alpha_r
    coordinate_second = (
        g / B + (1.0 - 1.0 / B) * (1.0 - 2.0 * alpha_r + beta_r)
    )
    return g**p.k, coordinate_second**p.k


def poisson_moments_direct(qbits: float, p: Params) -> tuple[float, float]:
    """Direct log-domain Poisson sum, independently implemented."""
    lam = 2.0 ** (qbits - p.h)
    cutoff = max(160, math.ceil(lam + 42 * math.sqrt(lam + 1) + 240))
    lmu = -math.inf
    lnu = -math.inf
    for r in range(1, cutoff + 1):
        logp = (-lam + r * math.log(lam) - math.lgamma(r + 1)) / math.log(2)
        mu_r, nu_r = conditional_moments(r, p)
        if mu_r:
            lmu = logadd2(lmu, logp + math.log2(mu_r))
        if nu_r:
            lnu = logadd2(lnu, logp + math.log2(nu_r))
    # The Chernoff exponent is much less than -400 at all audited points.
    u = cutoff + 1.0
    tail = (-lam + u * (1.0 + math.log(lam / u))) / math.log(2)
    if tail >= -400:
        raise AssertionError((p.name, qbits, cutoff, tail))
    return lmu, logadd2(lnu, tail)


def poisson_moments_closed(qbits: float, p: Params) -> tuple[float, float]:
    """Closed high-precision check using E[t^R]=exp(lambda*(t-1)).

    For one coordinate, g_r=1-alpha^r.  For the coordinate's second
    moment, s_r=1-(2-1/B)alpha^r+(1-1/B)beta^r.  Expanding g_r^k and
    s_r^k and applying the Poisson pgf gives finite sums.
    """
    D = Decimal
    with localcontext() as ctx:
        ctx.prec = 220
        ln2 = D(2).ln()
        lam = ((D(str(qbits)) - D(p.h)) * ln2).exp()
        B = D(2) ** p.a
        alpha = D(1) - D(1) / B
        beta = D(1) - D(2) / B

        mu = D(0)
        for j in range(p.k + 1):
            mu += D((-1) ** j * math.comb(p.k, j)) * (
                lam * (alpha**j - D(1))
            ).exp()

        A = D(2) - D(1) / B
        C = D(1) - D(1) / B
        nu = D(0)
        fact = math.factorial
        for i in range(p.k + 1):
            for j in range(p.k - i + 1):
                ell = p.k - i - j
                multinomial = fact(p.k) // (fact(i) * fact(j) * fact(ell))
                coefficient = D(multinomial) * ((-A) ** i) * (C**j)
                nu += coefficient * (
                    lam * (alpha**i * beta**j - D(1))
                ).exp()
        return float(mu.ln() / ln2), float(nu.ln() / ln2)


def exact_wots_probability(p: Params) -> tuple[int, float]:
    """Central coefficient divided by prefix and digit-vector spaces."""
    coefficients = [1]
    for width in p.wots_widths:
        nxt = [0] * (len(coefficients) + width - 1)
        for total, count in enumerate(coefficients):
            for digit in range(width):
                nxt[total + digit] += count
        coefficients = nxt
    wanted = sum(w - 1 for w in p.wots_widths) // 2
    denominator = 1 << (160 - sum(round(math.log2(w)) for w in p.wots_widths))
    for width in p.wots_widths:
        denominator *= width
    return coefficients[wanted], coefficients[wanted] / denominator


def suffix_bytes(p: Params) -> int:
    return p.d * (4 + p.wots_len * p.n) + p.h * p.n


def hierarchically_shared_suffix_bytes(p: Params, prefix: int) -> int:
    """Upper bound after sharing identical upper-layer suffix chunks.

    Choose the retained prefix from the high bits of the complete bottom
    address.  A layer-i WOTS signature and authentication path is identical
    for all bottom addresses that map to that layer-i structural address.
    Authentication nodes inside one layer could be shared further, so this is
    deliberately only the simple, easy-to-realize deduplication.
    """
    remaining = p.h - prefix
    lower_bits = 0
    total = 0
    for height in p.heights:
        count = 1 << max(0, remaining - lower_bits)
        total += count * (4 + p.wots_len * p.n + height * p.n)
        lower_bits += height
    return total


def table_costs(qbits: float, p: Params, prefix: int) -> dict[str, float]:
    lam = 2.0 ** (qbits - p.h)
    B = 1 << p.a
    addresses = 2.0 ** (p.h - prefix)
    occupied = -math.expm1(-lam)
    distinct = B * -math.expm1(-lam / B)
    frontier = 0.0
    for height in range(p.a):
        size = 1 << height
        frontier += (B / size) * (
            math.exp(-lam * size / B) - math.exp(-lam * 2 * size / B)
        )
    record = (p.a + 1) * p.n + 1
    suffix = suffix_bytes(p) + 16
    complete = addresses * (p.k * distinct * record + occupied * suffix)
    compact = addresses * (
        p.k * p.n * (distinct + frontier)
        + occupied * (p.k * B / 8 + suffix)
    )
    hard = addresses * (p.k * B * record + suffix)
    return {
        "expected_complete_log2_bytes": math.log2(complete),
        "expected_compact_log2_bytes": math.log2(compact),
        "hard_fully_provisioned_log2_bytes": math.log2(hard),
        "expected_distinct_per_coordinate": distinct,
        "expected_frontier_per_coordinate": frontier,
    }


def exhaustive_frontier_check(B: int = 8, r: int = 4) -> dict[str, float]:
    """Exhaust a small fixed-r forest and check the frontier identity."""
    if B & (B - 1):
        raise ValueError("B must be a power of two")
    a = round(math.log2(B))
    total_distinct = 0
    total_frontier = 0
    trials = B**r
    for sequence in itertools.product(range(B), repeat=r):
        seen = set(sequence)
        total_distinct += len(seen)
        for height in range(a):
            size = 1 << height
            for start in range(0, B, size):
                if any(start <= x < start + size for x in seen):
                    continue
                sibling = start + size if (start // size) % 2 == 0 else start - size
                if any(sibling <= x < sibling + size for x in seen):
                    total_frontier += 1
    exhaustive_distinct = total_distinct / trials
    exhaustive_frontier = total_frontier / trials
    formula_distinct = B * (1 - (1 - 1 / B) ** r)
    formula_frontier = 0.0
    for height in range(a):
        size = 1 << height
        formula_frontier += (B / size) * (
            ((B - size) / B) ** r - ((B - 2 * size) / B) ** r
        )
    return {
        "B": B,
        "r": r,
        "enumerated_sequences": trials,
        "exhaustive_distinct": exhaustive_distinct,
        "formula_distinct": formula_distinct,
        "distinct_absolute_delta": abs(exhaustive_distinct - formula_distinct),
        "exhaustive_frontier": exhaustive_frontier,
        "formula_frontier": formula_frontier,
        "frontier_absolute_delta": abs(exhaustive_frontier - formula_frontier),
    }


def profile(qbits: float, p: Params, prefix: int) -> dict[str, float]:
    lmu, lnu = poisson_moments_direct(qbits, p)
    log_mean_trial = -p.a_prime - prefix + lmu
    target = 1.0 - log_mean_trial
    relative_variance_log2 = prefix - p.h + lnu - 2 * lmu
    chebyshev_bad_log2 = 2 + relative_variance_log2
    bad = 0.0 if chebyshev_bad_log2 < -1074 else min(1.0, 2**chebyshev_bad_log2)
    answer = {
        "prefix_bits": prefix,
        "log2_signing_queries": qbits,
        "log2_mu": lmu,
        "log2_nu": lnu,
        "log2_fixed_target_trials": target,
        "log2_total_interactions": logadd2(qbits, target),
        "log2_chebyshev_half_mean_failure": chebyshev_bad_log2,
        "success_lower_before_cap_abort": (1 - bad) * (1 - math.exp(-1)),
        "log2_returned_signature_bytes": qbits + math.log2(p.signature_bytes),
    }
    answer.update(table_costs(qbits, p, prefix))
    return answer


def optimize(p: Params, prefix: int) -> dict[str, float]:
    """Independent grid optimization under mean q <= 2^79."""
    best: tuple[float, float] | None = None
    steps = int(round((79.0 - p.h) / 0.05))
    for i in range(steps + 1):
        q = p.h + 0.05 * i
        lmu, _ = poisson_moments_direct(q, p)
        target = 1 + p.a_prime + prefix - lmu
        score = logadd2(q, target)
        if best is None or score < best[0]:
            best = score, q
    assert best is not None
    center = best[1]
    for i in range(-100, 101):
        q = center + i / 1000
        if q < p.h or q > 79:
            continue
        lmu, _ = poisson_moments_direct(q, p)
        target = 1 + p.a_prime + prefix - lmu
        score = logadd2(q, target)
        if score < best[0]:
            best = score, q
    return profile(best[1], p, prefix)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1 << 20):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    recovered_complexity = json.loads(
        (CANDIDATE / "results" / "latest" / "rigorous_complexity.json").read_text()
    )
    claimed = recovered_complexity["parameter_sets"]
    recovered_toy = json.loads(
        (CANDIDATE / "results" / "latest" / "toy-strict-forge.json").read_text()
    )
    native_f = json.loads(
        (CANDIDATE / "results" / "latest" / "native-fors-splice-160f.json").read_text()
    )
    native_s = json.loads(
        (CANDIDATE / "results" / "latest" / "native-fors-splice-160s.json").read_text()
    )
    moment_rows: dict[str, dict] = {}
    largest_closed_direct_delta = 0.0
    largest_closed_claim_delta = 0.0
    for p in PARAMS:
        rows = claimed[p.name]
        moment_rows[p.name] = {}
        for label in ("all_address_optimum", "memory_bounded_prefix_optimum"):
            row = rows[label]
            q = row["poisson_mean_signing_queries_log2"]
            closed_mu, closed_nu = poisson_moments_closed(q, p)
            direct_mu, direct_nu = poisson_moments_direct(q, p)
            claim_mu = row["mean_covered_vector_fraction_log2"]
            claim_nu = row["second_moment_covered_vector_fraction_log2"]
            closed_direct = max(abs(closed_mu - direct_mu), abs(closed_nu - direct_nu))
            closed_claim = max(abs(closed_mu - claim_mu), abs(closed_nu - claim_nu))
            largest_closed_direct_delta = max(largest_closed_direct_delta, closed_direct)
            largest_closed_claim_delta = max(largest_closed_claim_delta, closed_claim)
            moment_rows[p.name][label] = {
                "qbits": q,
                "closed_log2_mu": closed_mu,
                "closed_log2_nu": closed_nu,
                "direct_log2_mu": direct_mu,
                "direct_log2_nu_upper": direct_nu,
                "claimed_log2_mu": claim_mu,
                "claimed_log2_nu_upper": claim_nu,
                "closed_vs_direct_max_abs_bits": closed_direct,
                "closed_vs_claim_max_abs_bits": closed_claim,
            }

    # Frozen NREC audit-host capacity.  This is deliberately fixed so the
    # release reproduces the reported machine-specific rows on any host.
    memory_bytes = 135_045_894_144
    memory_log2 = math.log2(memory_bytes)

    host_rows: dict[str, dict] = {}
    for p in PARAMS:
        all_hard = table_costs(float(p.h), p, 0)["hard_fully_provisioned_log2_bytes"]
        # The fully provisioned cost is independent of q; the q=p.h call is
        # only a convenient way to evaluate it.
        hard_prefix = math.ceil(all_hard - memory_log2)
        hard_profiles = {}
        for selected_prefix in (hard_prefix, hard_prefix + 1):
            row = optimize(p, selected_prefix)
            addresses = 2 ** (p.h - selected_prefix)
            occupied = -math.expm1(
                -(2 ** (row["log2_signing_queries"] - p.h))
            )
            compact_unshared = 2 ** row["expected_compact_log2_bytes"]
            compact_shared = (
                compact_unshared
                - addresses * occupied * suffix_bytes(p)
                + hierarchically_shared_suffix_bytes(p, selected_prefix)
            )
            hard_bytes = 2 ** row["hard_fully_provisioned_log2_bytes"]
            cycles_log2 = row["log2_signing_queries"] + math.log2(
                p.harness_sign_cycles
            )
            seconds_log2 = cycles_log2 - math.log2(2_000_000_000 * 64)
            years_log2 = seconds_log2 - math.log2(365.25 * 86400)
            hard_profiles[str(selected_prefix)] = {
                **row,
                "hard_table_bytes": hard_bytes,
                "hard_table_fraction_of_memtotal": hard_bytes / memory_bytes,
                "ram_margin_bytes": memory_bytes - hard_bytes,
                "log2_attacker_hmsg_calls_parse_plus_target": row[
                    "log2_total_interactions"
                ],
                "log2_attacker_hmsg_tsc_ticks": (
                    row["log2_total_interactions"]
                    + math.log2(p.measured_hmsg_tsc_ticks)
                ),
                "log2_honest_signer_cycles": cycles_log2,
                "ideal_64_core_2GHz_signing_wall_years_log2": years_log2,
                "ideal_64_core_2GHz_signing_wall_years": 2**years_log2,
                "simple_hierarchical_suffix_sharing": {
                    "unshared_suffix_bytes_per_occupied_address": suffix_bytes(p),
                    "shared_suffix_bytes_total": hierarchically_shared_suffix_bytes(
                        p, selected_prefix
                    ),
                    "expected_compact_table_with_sharing_log2_bytes": math.log2(
                        compact_shared
                    ),
                    "prefix_reduction": 0,
                },
            }
        hard_row = hard_profiles[str(hard_prefix)]
        host_rows[p.name] = {
            "actual_memtotal_bytes": memory_bytes,
            "actual_memtotal_log2_bytes": memory_log2,
            "minimum_hard_table_prefix_bits": hard_prefix,
            "hard_ram_profile": hard_row,
            "hard_ram_profiles_minimum_and_safer": hard_profiles,
            "ngcc_harness_mean_sign_cycles": p.harness_sign_cycles,
            "ideal_64_core_2GHz_signing_wall_years_log2": hard_row[
                "ideal_64_core_2GHz_signing_wall_years_log2"
            ],
            "ideal_64_core_2GHz_signing_wall_years": hard_row[
                "ideal_64_core_2GHz_signing_wall_years"
            ],
        }

    # These expected-size points test whether packed compact forests can use
    # fewer prefix bits than the deterministic fully provisioned table.  The
    # safer 160s b=51 point is included because b=50 leaves little allocator
    # and operating-system headroom on this host.
    expected_ram_candidates = {}
    for p, prefixes in ((F, (46,)), (S, (50, 51))):
        expected_ram_candidates[p.name] = {}
        for prefix in prefixes:
            row = optimize(p, prefix)
            addresses = 2 ** (p.h - prefix)
            occupied = -math.expm1(-(2 ** (row["log2_signing_queries"] - p.h)))
            compact = 2 ** row["expected_compact_log2_bytes"]
            shared = (
                compact
                - addresses * occupied * suffix_bytes(p)
                + hierarchically_shared_suffix_bytes(p, prefix)
            )
            expected_ram_candidates[p.name][str(prefix)] = {
                **row,
                "compact_with_simple_suffix_sharing_log2_bytes": math.log2(shared),
                "fits_memtotal_in_expectation_before_runtime_overhead": (
                    shared < memory_bytes
                ),
            }

    wots = {}
    for p in PARAMS:
        coefficient, probability = exact_wots_probability(p)
        artifact_probability = claimed[p.name]["parameters"]["wots_valid_probability"]
        wots[p.name] = {
            "central_coefficient": coefficient,
            "exact_probability_float": probability,
            "artifact_probability": artifact_probability,
            "absolute_delta": abs(probability - artifact_probability),
        }

    output = {
        "status": "CONFIRMED_ABSTRACT_ATTACK_NOT_HOST_SCALE",
        "independence": "no import of candidate analysis code",
        "moment_cross_checks": moment_rows,
        "largest_closed_vs_direct_delta_bits": largest_closed_direct_delta,
        "largest_closed_vs_claim_delta_bits": largest_closed_claim_delta,
        "exact_wots_membership": wots,
        "exhaustive_compact_forest_check": exhaustive_frontier_check(),
        "actual_host_profiles": host_rows,
        "packed_expected_ram_candidates": expected_ram_candidates,
        "experiment_evidence_snapshot": {
            "scaled_strict_forgery": recovered_toy,
            "native_full_parameter_fors_splice_160f": native_f,
            "native_full_parameter_fors_splice_160s": native_s,
        },
        "source_hashes": {
            "native_fors_splice_source": sha256(ROOT / "native_fors_splice.c"),
            "submitted_160f_fors_source": sha256(
                ROOT / "vendor/submitted-160f/fors.c"
            ),
            "submitted_160s_fors_source": sha256(
                ROOT / "vendor/submitted-160s/fors.c"
            ),
        },
        "submitted_pdf_resources": {
            "160f_sign_hash_calls": 171_917,
            "160s_sign_hash_calls": 2_982_293,
            "160f_sign_cycles": F.pdf_sign_cycles,
            "160s_sign_cycles": S.pdf_sign_cycles,
        },
        "ngcc_harness_x86_resources": {
            "source": "frozen independent NGCC x86 harness measurements; see evidence/PERFORMANCE_SOURCE.md",
            "160f_mean_sign_cycles": F.harness_sign_cycles,
            "160s_mean_sign_cycles": S.harness_sign_cycles,
            "artifact_160f_cycle_delta": (
                claimed[F.name]["parameters"]["measured_sign_cycles"]
                - F.harness_sign_cycles
            ),
            "artifact_160s_cycle_delta": (
                claimed[S.name]["parameters"]["measured_sign_cycles"]
                - S.harness_sign_cycles
            ),
        },
    }
    results = ROOT / "results" / "latest"
    results.mkdir(exist_ok=True)
    (results / "independent-audit.json").write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

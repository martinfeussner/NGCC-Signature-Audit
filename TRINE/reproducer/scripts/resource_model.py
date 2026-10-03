#!/usr/bin/env python3
"""Independent ideal-model calculations for the TRINE-I seed-collision review.

The fixed-index route is exact in the stated random-oracle/uniform-seed model.
The all-round route uses the standard sparse independent-Poisson edge model;
the script labels it as an approximation and separately simulates the exact
fixed-weight challenge generator at a reduced seed size.
"""

import argparse
import itertools
import json
import math
import random


PROFILES = {
    "Balanced-I": dict(r=138, K=52, X=1, sig_bytes=3124,
                       sign_cycles=10345068140, verify_cycles=5840471423,
                       measured_seed_to_cf_seconds=0.345799062),
    "ShortSig-I": dict(r=61, K=36, X=4, sig_bytes=1620,
                       sign_cycles=4875380743, verify_cycles=2167962778,
                       measured_seed_to_cf_seconds=0.342778750),
}

CPU_HZ = 1_996_249_000.0
MEASURED_FULL_CF_SECONDS = 0.00545916303
MEASURED_PARTIAL_SECONDS = 0.00059971063


def connected(n, edges_mask, pairs):
    seen = {0}
    changed = True
    while changed:
        changed = False
        for bit, (u, v) in enumerate(pairs):
            if not ((edges_mask >> bit) & 1):
                continue
            if u in seen and v not in seen:
                seen.add(v); changed = True
            if v in seen and u not in seen:
                seen.add(u); changed = True
    return len(seen) == n


def poisson_connectivity(logq, r, K, X, lam=128):
    """Connectivity probability under independent Poisson edge counts."""
    q = 2.0 ** logq
    probs = [K / (r * X)] * X + [(r - K) / r]
    pairs = list(itertools.combinations(range(X + 1), 2))
    edge_probs = []
    for u, v in pairs:
        mu = q * (q - 1.0) * r * probs[u] * probs[v] / (2.0 ** lam)
        edge_probs.append(-math.expm1(-mu))
    total = 0.0
    for mask in range(1 << len(pairs)):
        if not connected(X + 1, mask, pairs):
            continue
        p = 1.0
        for bit, ep in enumerate(edge_probs):
            p *= ep if ((mask >> bit) & 1) else (1.0 - ep)
        total += p
    return total


def bisect_logq(profile, target=0.5):
    lo, hi = 40.0, 80.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if poisson_connectivity(mid, **{k: profile[k] for k in ("r", "K", "X")}) < target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def fixed_table_probability(logq, logp, r, K, X, lam=128):
    """Exact ideal fixed-index success, with P distinct public table seeds."""
    q = 2.0 ** logq
    P = 2.0 ** logp
    alpha = (K / (r * X)) * P / (2.0 ** lam)
    ans = 0.0
    for s in range(X + 1):
        term = math.comb(X, s) * math.exp(q * math.log1p(-s * alpha))
        ans += (-1.0 if s & 1 else 1.0) * term
    return ans


def solve_logp(logq, profile, target=0.5):
    lo, hi = 0.0, 127.0
    for _ in range(120):
        mid = (lo + hi) / 2
        if fixed_table_probability(logq, mid, **{k: profile[k] for k in ("r", "K", "X")}) < target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def optimize_fixed_calls(profile):
    best = None
    # Smooth enough for this reporting precision; then refine around the best.
    for step in (0.01, 0.0001):
        if best is None:
            start, stop = 50.0, 78.0
        else:
            start, stop = best[1] - 0.03, best[1] + 0.03
        x = start
        while x <= stop + 1e-12:
            lp = solve_logp(x, profile)
            p_nonbase = profile["K"] / profile["r"]
            lcalls = math.log2(2.0 ** lp + p_nonbase * 2.0 ** x)
            candidate = (lcalls, x, lp)
            if best is None or candidate < best:
                best = candidate
            x += step
    return best


def optimize_fixed_weighted_cycles(profile, target_seconds):
    """Include deterministic seed-to-CF expansion for every table entry."""
    best = None
    p_nonbase = profile["K"] / profile["r"]
    seed_seconds = profile["measured_seed_to_cf_seconds"]
    for step in (0.01, 0.0001):
        if best is None:
            start, stop = 55.0, 76.0
        else:
            start, stop = best[1] - 0.03, best[1] + 0.03
        x = start
        while x <= stop + 1e-12:
            lp = solve_logp(x, profile)
            # measured_seed_seconds is the complete normative seed-to-CF path:
            # seeded Corank1Cal, retry, and canonical form.  Do not add a
            # second fingerprint evaluation on the table side.  A non-base
            # target record already contains its point and needs only the
            # selected fingerprint.
            seconds = 2.0**lp * seed_seconds + p_nonbase * 2.0**x * target_seconds
            candidate = (math.log2(seconds * CPU_HZ), x, lp,
                         math.log2(seconds))
            if best is None or candidate < best:
                best = candidate
            x += step
    return best


def challenge_vector(r, K, X, rng):
    out = [X] * r
    for pos in rng.sample(range(r), K):
        out[pos] = rng.randrange(X)
    return out


def one_simulation(seed_bits, q, r, K, X, rng):
    # Each table is round-index-separated, matching the conservative specification/source reading.
    tables = [dict() for _ in range(r)]
    graph = [set([i]) for i in range(X + 1)]
    pairs = list(itertools.combinations(range(X + 1), 2))
    for _ in range(q):
        labels = challenge_vector(r, K, X, rng)
        seeds = [rng.getrandbits(seed_bits) for _ in range(r)]
        for i, (label, seed) in enumerate(zip(labels, seeds)):
            prior = tables[i].setdefault(seed, set())
            for other in prior:
                if other != label:
                    graph[label].add(other); graph[other].add(label)
            prior.add(label)
    seen = {X}
    stack = [X]
    while stack:
        u = stack.pop()
        for v in graph[u]:
            if v not in seen:
                seen.add(v); stack.append(v)
    return len(seen) == X + 1


def simulate(profile, full_logq, trials, seed_bits, rng):
    scaled_logq = full_logq - (128 - seed_bits) / 2
    q = max(2, round(2.0 ** scaled_logq))
    wins = sum(one_simulation(seed_bits, q, profile["r"], profile["K"], profile["X"], rng)
               for _ in range(trials))
    p = wins / trials
    se = math.sqrt(max(p * (1 - p), 1e-30) / trials)
    return dict(seed_bits=seed_bits, signatures=q, trials=trials, successes=wins,
                empirical_probability=p, standard_error=se,
                poisson_probability=poisson_connectivity(math.log2(q) + (128-seed_bits)/2,
                                                          profile["r"], profile["K"], profile["X"]))


def report(profile_name, profile, trials, seed_bits, rng):
    all_logq = bisect_logq(profile)
    fixed_lp_at_allq = solve_logp(all_logq, profile)
    fixed_opt_calls, fixed_opt_q, fixed_opt_p = optimize_fixed_calls(profile)
    weighted_full = optimize_fixed_weighted_cycles(profile, MEASURED_FULL_CF_SECONDS)
    weighted_partial = optimize_fixed_weighted_cycles(profile, MEASURED_PARTIAL_SECONDS)
    log_sig_bits = math.log2(profile["sig_bytes"] * 8)
    log_r = math.log2(profile["r"])
    # Conservative storage record: 32-byte digest, 33-byte point, seed/labels/index padding.
    record_bytes = 80
    p_nonbase = profile["K"] / profile["r"]

    def public_table_resources(logq, logp, fingerprint_seconds):
        seconds = (2.0**logp * profile["measured_seed_to_cf_seconds"]
                   + p_nonbase * 2.0**logq * fingerprint_seconds)
        return {
            "log2_total_cycles": math.log2(seconds * CPU_HZ),
            "log2_serial_seconds": math.log2(seconds),
            "log2_honest_signer_cycles_from_spec_table":
                logq + math.log2(profile["sign_cycles"]),
            "log2_public_table_bytes_at_80_bytes_per_entry":
                logp + math.log2(record_bytes),
        }

    per_signature_processing_seconds = (
        (profile["r"] - profile["K"]) * profile["measured_seed_to_cf_seconds"]
        + profile["K"] * MEASURED_FULL_CF_SECONDS)
    return {
        "profile": profile_name,
        "parameters": profile,
        "all_round_poisson_median": {
            "log2_signature_queries": all_logq,
            "probability": poisson_connectivity(all_logq, profile["r"], profile["K"], profile["X"]),
            "log2_returned_signature_bits": all_logq + log_sig_bits,
            "log2_canonical_form_calls": all_logq + log_r,
            "log2_retained_bytes_at_80_bytes_per_round_record": all_logq + log_r + math.log2(record_bytes),
            "log2_honest_signer_cycles_from_spec_table": all_logq + math.log2(profile["sign_cycles"]),
            "log2_attacker_cycles_from_measured_decode_and_full_cf":
                all_logq + math.log2(per_signature_processing_seconds * CPU_HZ),
            "log2_attacker_serial_seconds_from_measured_decode_and_full_cf":
                all_logq + math.log2(per_signature_processing_seconds),
            "per_signature_processing_seconds": per_signature_processing_seconds,
            "processing_formula": "(r-K)*seed_to_CF + K*nonbase_full_CF",
            "model": "independent sparse Poisson edges; not an exact serialized-signature probability",
        },
        "fixed_index_public_table_at_all_round_query_count": {
            "log2_signature_queries": all_logq,
            "log2_distinct_public_table_seeds": fixed_lp_at_allq,
            "probability": fixed_table_probability(all_logq, fixed_lp_at_allq,
                                                   profile["r"], profile["K"], profile["X"]),
            "log2_returned_signature_bits": all_logq + log_sig_bits,
            "log2_fingerprint_calls": math.log2(2.0**fixed_lp_at_allq +
                (profile["K"]/profile["r"]) * 2.0**all_logq),
            "measured_full_cf_resources": public_table_resources(
                all_logq, fixed_lp_at_allq, MEASURED_FULL_CF_SECONDS),
            "model": "exact ideal RO/uniform-seed formula at one fixed round index",
        },
        "fixed_index_minimum_fingerprint_calls": {
            "log2_signature_queries": fixed_opt_q,
            "log2_distinct_public_table_seeds": fixed_opt_p,
            "log2_fingerprint_calls": fixed_opt_calls,
            "probability": fixed_table_probability(fixed_opt_q, fixed_opt_p,
                                                   profile["r"], profile["K"], profile["X"]),
            "log2_returned_signature_bits": fixed_opt_q + log_sig_bits,
            "measured_full_cf_resources": public_table_resources(
                fixed_opt_q, fixed_opt_p, MEASURED_FULL_CF_SECONDS),
        },
        "fixed_index_weighted_total_cpu": {
            "full_cf_baseline": {
                "log2_signature_queries": weighted_full[1],
                "log2_distinct_public_table_seeds": weighted_full[2],
                "log2_total_cycles": weighted_full[0],
                "log2_serial_seconds": weighted_full[3],
                "log2_returned_signature_bits": weighted_full[1] + log_sig_bits,
                "log2_honest_signer_cycles_from_spec_table":
                    weighted_full[1] + math.log2(profile["sign_cycles"]),
                "log2_public_table_bytes_at_80_bytes_per_entry":
                    weighted_full[2] + math.log2(record_bytes),
                "success_probability": fixed_table_probability(
                    weighted_full[1], weighted_full[2], profile["r"], profile["K"], profile["X"]),
            },
            "partial_prefilter_heuristic": {
                "log2_signature_queries": weighted_partial[1],
                "log2_distinct_public_table_seeds": weighted_partial[2],
                "log2_total_cycles": weighted_partial[0],
                "log2_serial_seconds": weighted_partial[3],
                "log2_returned_signature_bits": weighted_partial[1] + log_sig_bits,
                "log2_honest_signer_cycles_from_spec_table":
                    weighted_partial[1] + math.log2(profile["sign_cycles"]),
                "log2_public_table_bytes_at_80_bytes_per_entry":
                    weighted_partial[2] + math.log2(record_bytes),
                "success_probability": fixed_table_probability(
                    weighted_partial[1], weighted_partial[2], profile["r"], profile["K"], profile["X"]),
            },
            "measurement_basis": {
                "cpu_hz": CPU_HZ,
                "seed_to_cf_seconds": profile["measured_seed_to_cf_seconds"],
                "full_cf_seconds": MEASURED_FULL_CF_SECONDS,
                "partial_prefilter_seconds": MEASURED_PARTIAL_SECONDS,
                "warning": "machine measurements are concrete estimates, not exact mathematical costs",
            },
        },
        "reduced_seed_fixed_weight_simulation": simulate(profile, all_logq, trials, seed_bits, rng),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    ap.add_argument("--seed-bits", type=int, default=16)
    ap.add_argument("--rng-seed", type=int, default=0x5452494E45)
    ap.add_argument("--output", default="complexity_results.json")
    args = ap.parse_args()
    rng = random.Random(args.rng_seed)
    data = {
        "rng_seed": args.rng_seed,
        "notes": [
            "A round index is included in the seed decoder; only equal-index collisions are counted.",
            "The fixed-index formula is sum_s (-1)^s C(X,s)(1-s*K*P/(r*X*2^lambda))^q.",
            "All-round medians use a sparse Poisson graph; fixed-weight simulation is an independent diagnostic.",
        ],
        "profiles": [report(name, p, args.trials, args.seed_bits, rng) for name, p in PROFILES.items()],
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

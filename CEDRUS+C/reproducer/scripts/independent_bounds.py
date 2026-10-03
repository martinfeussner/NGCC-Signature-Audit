#!/usr/bin/env python3
"""Independent direct-probability check of the two claimed CEDRUS+C rows.

This intentionally does not import the candidate's complexity code.  It uses
the Poisson recurrence p[r+1] = p[r] lambda/(r+1), direct summation, and the
occupancy indicator identities for E[Z] and E[Z^2].
"""

from __future__ import annotations

import json
import math
from pathlib import Path


def row(name: str, h: int, a: int, k: int, aprime: int,
        qbits: float, retained_prefix_bits: int) -> dict[str, float | str]:
    leaves = 2**a
    lam = 2.0 ** (qbits - h)
    probability = math.exp(-lam)
    mean_z = 0.0
    mean_z2 = 0.0
    total_probability = probability

    # All selected rows have lambda < 512.  4096 terms leave a tail far
    # below double precision and also provide an explicit probability check.
    for r in range(1, 4097):
        probability *= lam / r
        total_probability += probability
        one_unseen = (1.0 - 1.0 / leaves) ** r
        two_unseen = (1.0 - 2.0 / leaves) ** r
        seen_fraction = 1.0 - one_unseen
        pair_seen = 1.0 - 2.0 * one_unseen + two_unseen
        coordinate_second = seen_fraction / leaves + (1.0 - 1.0 / leaves) * pair_seen
        mean_z += probability * seen_fraction**k
        mean_z2 += probability * coordinate_second**k

    mean_trial = 2.0 ** (-aprime-retained_prefix_bits) * mean_z
    target_trials = 2.0 / mean_trial
    interactions = 2.0**qbits + target_trials
    relative_variance_bound = mean_z2 * 2.0 ** (retained_prefix_bits-h) / mean_z**2
    chebyshev_bad = min(1.0, 4.0 * relative_variance_bound)
    success_lower = (1.0-chebyshev_bad) * (1.0-math.exp(-1.0))
    return {
        "name": name,
        "lambda": lam,
        "summed_poisson_mass": total_probability,
        "log2_mean_covered_fraction": math.log2(mean_z),
        "log2_second_moment": math.log2(mean_z2),
        "log2_target_trials": math.log2(target_trials),
        "log2_total_oracle_interactions": math.log2(interactions),
        "chebyshev_bad_probability_upper": chebyshev_bad,
        "success_probability_lower": success_lower,
    }


def main() -> None:
    checks = [
        row("160f-all", 66, 7, 30, 9, 70.928, 0),
        row("160f-prefix6", 66, 7, 30, 9, 71.220, 6),
        row("160s-all", 67, 12, 13, 15, 74.760, 0),
        row("160s-prefix11", 67, 12, 13, 15, 75.587, 11),
    ]
    expected = {
        "160f-all": (-56.63951083376242, 66.63951083376242, 70.99999935610123),
        "160f-prefix6": (-50.933863367831094, 66.9338633678311, 71.29211396938855),
        "160s-all": (-55.13877978799165, 71.13877978799165, 74.87272028558861),
        "160s-prefix11": (-44.98160794618627, 71.98160794618627, 75.70091594329357),
    }
    all_match = True
    for result in checks:
        e = expected[str(result["name"])]
        deltas = [
            abs(float(result["log2_mean_covered_fraction"])-e[0]),
            abs(float(result["log2_target_trials"])-e[1]),
            abs(float(result["log2_total_oracle_interactions"])-e[2]),
        ]
        result["max_abs_log2_delta_from_candidate"] = max(deltas)
        result["candidate_values_match_to_1e_9"] = max(deltas) < 1e-9
        all_match &= bool(result["candidate_values_match_to_1e_9"])
    out = {"all_match": all_match, "checks": checks}
    dest = Path(__file__).resolve().parent.parent / "results" / "latest" / "independent-bounds.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

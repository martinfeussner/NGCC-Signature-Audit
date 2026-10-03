#!/usr/bin/env python3
"""Independent exhaustive and Monte Carlo checks of the occupancy moments."""

from __future__ import annotations

import itertools
import json
import math
import random
from pathlib import Path


def formula(B: int, k: int, r: int) -> tuple[float, float]:
    q1 = (1.0 - 1.0 / B) ** r
    g = 1.0 - q1
    p2 = 1.0 - 2.0 * q1 + (1.0 - 2.0 / B) ** r
    s = g / B + (1.0 - 1.0 / B) * p2
    return g ** k, s ** k


def exhaustive_coordinate(B: int, r: int) -> tuple[float, float]:
    vals = []
    for draws in itertools.product(range(B), repeat=r):
        vals.append(len(set(draws)) / B)
    return sum(vals) / len(vals), sum(x * x for x in vals) / len(vals)


def monte_carlo(B: int, k: int, r: int, trials: int, seed: int) -> tuple[float, float]:
    rng = random.Random(seed)
    first = second = 0.0
    for _ in range(trials):
        z = 1.0
        for _ in range(k):
            z *= len({rng.randrange(B) for _ in range(r)}) / B
        first += z
        second += z * z
    return first / trials, second / trials


def main() -> None:
    B, k, r = 4, 3, 4
    cg, cs = exhaustive_coordinate(B, r)
    f1, f2 = formula(B, k, r)
    assert abs(f1 - cg ** k) < 1e-15
    assert abs(f2 - cs ** k) < 1e-15
    trials = 200_000
    m1, m2 = monte_carlo(B, k, r, trials, 0xC0DEC)
    # Loose deterministic gates: about 6+ standard deviations at this N.
    assert abs(m1 - f1) < 0.003
    assert abs(m2 - f2) < 0.003
    out = {
        "toy_parameters": {"B": B, "k": k, "r": r},
        "exhaustive_coordinate_mean": cg,
        "exhaustive_coordinate_second_moment": cs,
        "formula_vector_mean": f1,
        "formula_vector_second_moment": f2,
        "monte_carlo_trials": trials,
        "monte_carlo_vector_mean": m1,
        "monte_carlo_vector_second_moment": m2,
        "absolute_mean_error": abs(m1 - f1),
        "absolute_second_moment_error": abs(m2 - f2),
        "status": "PASS",
    }
    path = Path(__file__).resolve().parent.parent / "results" / "latest" / "moment-check.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

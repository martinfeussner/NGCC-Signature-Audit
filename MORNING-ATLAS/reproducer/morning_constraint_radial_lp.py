#!/usr/bin/env python3
"""Public radial cutting-plane estimator for MORNING response constraints.

All inequalities are normalized to X*s >= b.  The all-zero vector is always
feasible, so feasibility alone cannot recover s.  The first-gate acceptance
normalizer favors feasible candidates with a broader distribution of c*s.
This script uses squared Euclidean norm as a deterministic Gaussian surrogate:
starting from a public bound-moment direction, it repeatedly maximizes the
current radial direction over the feasible polytope.

Only a small working set is sent to HiGHS.  Every proposed point is checked
against all public inequalities, and violated rows are added until the point is
globally feasible.  An optional secret is used only for calibration metrics.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from scipy.optimize import linprog

from morning_constraint_solve import read_constraints


ETA = 16
LOWEST_BOUND = -495.0
LP_FEASIBILITY_TOLERANCE = 1e-6


def calibration(estimate: np.ndarray, truth: np.ndarray | None) -> str:
    if truth is None:
        return ""
    error = estimate - truth
    return (
        f" rmse={np.sqrt(np.mean(error * error)):.9f}"
        f" max_error={np.max(np.abs(error)):.9f}"
        f" correlation={np.corrcoef(estimate, truth)[0, 1]:.9f}"
        f" rounded_exact={np.count_nonzero(np.rint(estimate) == truth)}/{len(truth)}"
    )


def public_start(x: np.ndarray, bound: np.ndarray) -> np.ndarray:
    """Linear projection of the censored-bound moment, used only as direction."""
    target = 2.0 * bound - LOWEST_BOUND
    gram = x.T @ x
    rhs = x.T @ target
    estimate = np.linalg.solve(gram + 1e-3 * np.eye(x.shape[1]), rhs)
    norm = np.linalg.norm(estimate)
    if norm == 0:
        raise ValueError("zero public start")
    return estimate / norm


def maximize_direction(
    x: np.ndarray,
    bound: np.ndarray,
    direction: np.ndarray,
    active: set[int],
    add_rows: int,
    max_cuts: int,
):
    for cut in range(max_cuts):
        indices = np.fromiter(active, dtype=np.int64)
        result = linprog(
            -direction,
            A_ub=-x[indices],
            b_ub=-bound[indices],
            bounds=[(-ETA, ETA)] * x.shape[1],
            method="highs",
        )
        if not result.success:
            raise RuntimeError(f"LP failed: {result.status} {result.message}")
        estimate = result.x
        violation = bound - x @ estimate
        bad = np.flatnonzero(violation > LP_FEASIBILITY_TOLERANCE)
        if len(bad) == 0:
            return estimate, cut + 1
        take_count = min(add_rows, len(bad))
        take = bad[
            np.argpartition(violation[bad], -take_count)[-take_count:]
        ]
        old_size = len(active)
        active.update(take.tolist())
        if len(active) == old_size:
            raise RuntimeError(
                "cutting plane stalled on active rows: "
                f"max_violation={violation[bad].max():.12g} "
                f"tolerance={LP_FEASIBILITY_TOLERANCE:.12g}"
            )
    raise RuntimeError(f"cutting plane did not converge in {max_cuts} rounds")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("constraints", type=Path)
    parser.add_argument("--secret", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--outer", type=int, default=10)
    parser.add_argument("--initial-rows", type=int, default=2000)
    parser.add_argument("--add-rows", type=int, default=2000)
    parser.add_argument("--max-cuts", type=int, default=30)
    args = parser.parse_args()

    n, ell, kappa, signatures, rows = read_constraints(args.constraints)
    truth = None
    if args.secret is not None:
        truth = np.loadtxt(args.secret, dtype=np.float64).reshape(ell, n)
    print(
        f"signatures={signatures} constraints={len(rows)} n={n} l={ell} "
        f"kappa={kappa} outer={args.outer}",
        flush=True,
    )

    estimates = []
    for polynomial in range(ell):
        selected = rows[rows["poly"] == polynomial]
        senses = selected["sense"].astype(np.float64)
        x = selected["row"].astype(np.float64) * senses[:, None]
        bound = selected["bound"].astype(np.float64) * senses
        direction = public_start(x, bound)
        initial_count = min(args.initial_rows, len(bound))
        active = set(
            np.argpartition(bound, -initial_count)[-initial_count:].tolist()
        )
        estimate = None
        for outer in range(args.outer):
            estimate, cuts = maximize_direction(
                x, bound, direction, active, args.add_rows, args.max_cuts
            )
            rounded = np.rint(estimate)
            rounded_bad = int(np.count_nonzero(x @ rounded < bound))
            print(
                f"poly={polynomial} outer={outer} active={len(active)} cuts={cuts} "
                f"norm={np.linalg.norm(estimate):.9f} "
                f"rounded_violations={rounded_bad}"
                f"{calibration(estimate, None if truth is None else truth[polynomial])}",
                flush=True,
            )
            new_direction = estimate / np.linalg.norm(estimate)
            if np.max(np.abs(new_direction - direction)) < 1e-10:
                direction = new_direction
                break
            direction = new_direction
        assert estimate is not None
        estimates.append(estimate)

    estimate = np.vstack(estimates)
    if truth is not None:
        error = estimate - truth
        print(
            f"all rmse={np.sqrt(np.mean(error * error)):.9f} "
            f"max_error={np.max(np.abs(error)):.9f} "
            f"correlation={np.corrcoef(estimate.ravel(), truth.ravel())[0, 1]:.9f} "
            f"rounded_exact={np.count_nonzero(np.rint(estimate) == truth)}/{truth.size}",
            flush=True,
        )
    if args.output is not None:
        np.savez(
            args.output,
            continuous=estimate,
            rounded=np.rint(estimate).astype(np.int16),
        )


if __name__ == "__main__":
    main()

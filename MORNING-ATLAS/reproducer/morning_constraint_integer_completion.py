#!/usr/bin/env python3
"""Integer completion of a public MORNING radial response estimate.

Each coefficient is restricted to floor/ceil of the public continuous estimate.
For every polynomial, a binary MILP maximizes the same frozen radial direction
under the closest public response constraints.  Its incumbent is then checked
against every response inequality.  If a public full-t LWR instance is supplied,
the assembled secret is validated by the exact residual interval [-16,15].

An optional secret is diagnostic only and never affects bounds, constraints,
objectives, stopping, or candidate selection.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp

from morning_constraint_solve import read_constraints
from morning_lwr_milp import centered, read_lwr


ETA = 16


def lwr_residual(candidate: np.ndarray, lwr_path: Path):
    n, k, ell, q, p, matrix, target = read_lwr(lwr_path)
    if candidate.shape != (ell, n):
        raise ValueError("candidate/LWR dimension mismatch")
    product = np.zeros((k, n), dtype=np.int64)
    for out_polynomial in range(k):
        for secret_polynomial in range(ell):
            ordinary = np.convolve(
                matrix[out_polynomial, secret_polynomial].astype(np.int64),
                candidate[secret_polynomial].astype(np.int64),
            )
            folded = ordinary[:n].copy()
            folded[: n - 1] -= ordinary[n:]
            product[out_polynomial] += folded
    residual = centered(product - 32 * target, q)
    return residual


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("constraints", type=Path)
    parser.add_argument("estimate", type=Path)
    parser.add_argument("--lwr", type=Path)
    parser.add_argument("--secret", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--working-rows", type=int, default=5000)
    parser.add_argument("--add-rows", type=int, default=2000)
    parser.add_argument("--time-limit", type=float, default=120.0)
    parser.add_argument("--max-cuts", type=int, default=5)
    args = parser.parse_args()

    n, ell, kappa, signatures, rows = read_constraints(args.constraints)
    estimate = np.load(args.estimate)["continuous"].astype(np.float64)
    if estimate.shape != (ell, n):
        raise ValueError("estimate shape mismatch")
    truth = None
    if args.secret is not None:
        truth = np.loadtxt(args.secret, dtype=np.int64).reshape(ell, n)
    print(
        f"signatures={signatures} constraints={len(rows)} n={n} l={ell} "
        f"kappa={kappa} time_limit={args.time_limit}",
        flush=True,
    )

    candidates = []
    for polynomial in range(ell):
        selected = rows[rows["poly"] == polynomial]
        senses = selected["sense"].astype(np.float64)
        x = selected["row"].astype(np.float64) * senses[:, None]
        bound = selected["bound"].astype(np.float64) * senses
        center = estimate[polynomial]
        lower = np.maximum(-ETA, np.floor(center))
        upper = np.minimum(ETA, np.ceil(center))
        slack = x @ center - bound
        initial_count = min(args.working_rows, len(bound))
        active = set(np.argpartition(slack, initial_count - 1)[:initial_count].tolist())
        candidate = None
        started = time.monotonic()
        for cut in range(args.max_cuts):
            remaining = args.time_limit - (time.monotonic() - started)
            if remaining <= 0:
                break
            indices = np.fromiter(active, dtype=np.int64)
            result = milp(
                -center,
                integrality=np.ones(n),
                bounds=Bounds(lower, upper),
                constraints=LinearConstraint(x[indices], bound[indices], np.inf),
                options={
                    "time_limit": remaining,
                    "mip_rel_gap": 0.0,
                    "presolve": True,
                },
            )
            if result.x is None:
                print(
                    f"poly={polynomial} cut={cut} status={result.status} "
                    f"no_incumbent message={result.message}",
                    flush=True,
                )
                break
            candidate = np.rint(result.x).astype(np.int16)
            violation = bound - x @ candidate
            bad = np.flatnonzero(violation > 0)
            fields = [
                f"poly={polynomial}",
                f"cut={cut}",
                f"status={result.status}",
                f"active={len(active)}",
                f"full_violations={len(bad)}",
                f"objective={center @ candidate:.9f}",
            ]
            if truth is not None:
                error = candidate.astype(np.int64) - truth[polynomial]
                fields.extend(
                    [
                        f"exact={np.count_nonzero(error == 0)}/{n}",
                        f"rmse={np.sqrt(np.mean(error.astype(float) ** 2)):.9f}",
                    ]
                )
            print(" ".join(fields), flush=True)
            if len(bad) == 0:
                break
            take_count = min(args.add_rows, len(bad))
            take = bad[
                np.argpartition(violation[bad], -take_count)[-take_count:]
            ]
            active.update(take.tolist())
        if candidate is None:
            raise RuntimeError(f"no integer incumbent for polynomial {polynomial}")
        full_bad = int(np.count_nonzero(x @ candidate < bound))
        if full_bad:
            raise RuntimeError(
                f"polynomial {polynomial} incumbent violates {full_bad} public rows"
            )
        candidates.append(candidate)

    candidate = np.vstack(candidates)
    if args.lwr is not None:
        residual = lwr_residual(candidate, args.lwr)
        valid = bool(np.all((residual >= -16) & (residual <= 15)))
        print(
            f"lwr_residual=[{residual.min()},{residual.max()}] "
            f"lwr_valid={str(valid).lower()} "
            f"lwr_coefficients_valid={np.count_nonzero((residual >= -16) & (residual <= 15))}/{residual.size}",
            flush=True,
        )
    if truth is not None:
        error = candidate.astype(np.int64) - truth
        print(
            f"all_exact={np.count_nonzero(error == 0)}/{truth.size} "
            f"rmse={np.sqrt(np.mean(error.astype(float) ** 2)):.9f} "
            f"max_error={np.max(np.abs(error))}",
            flush=True,
        )
    if args.output is not None:
        np.savez(args.output, secret=candidate)


if __name__ == "__main__":
    main()

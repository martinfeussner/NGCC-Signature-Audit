#!/usr/bin/env python3
"""Complete integer MORNING-ATLAS t0 candidates using public hint bounds."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp

from morning_hint_minimax import NegacyclicDesign, load


NOISE_BOUND = 8183


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("observations", type=Path)
    ap.add_argument("estimate", type=Path)
    ap.add_argument("--secret", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--margin", type=float, default=2.0)
    ap.add_argument("--time-limit", type=float, default=120.0)
    args = ap.parse_args()

    n, k, kappa, signatures, records = load(args.observations)
    estimates = np.load(args.estimate)["continuous"].reshape(k, n)
    truth = None if args.secret is None else np.loadtxt(args.secret).reshape(k, n)
    design = NegacyclicDesign(records["c"])
    completed = []
    print(f"signatures={signatures} n={n} k={k} kappa={kappa}", flush=True)

    for p in range(k):
        u = records["u"][:, p, :].astype(np.float64).reshape(-1)
        continuous = estimates[p]
        continuous_residual = design.apply(continuous).reshape(-1) - u
        initial = np.clip(np.rint(continuous), -511, 512)
        initial_residual = design.apply(initial, integer=True).reshape(-1) - u
        initial_violations = int(np.count_nonzero(np.abs(initial_residual) > NOISE_BOUND))

        if initial_violations == 0:
            candidate = initial.astype(np.int16)
            rounds = 0
        else:
            # Keep every nearly active row.  The coefficient box is restricted
            # to nearby integers; full public validation supplies any omitted
            # cutting planes.
            active = set(
                np.flatnonzero(
                    np.abs(continuous_residual) >= NOISE_BOUND - args.margin
                ).tolist()
            )
            active.update(np.flatnonzero(np.abs(initial_residual) > NOISE_BOUND).tolist())
            candidate = None
            for rounds in range(20):
                index = np.fromiter(sorted(active), dtype=np.int64)
                xmat = design.selected_rows(index)
                lower = u[index] - NOISE_BOUND
                upper = u[index] + NOISE_BOUND
                lo = np.maximum(-511, np.floor(continuous) - 1)
                hi = np.minimum(512, np.ceil(continuous) + 1)
                result = milp(
                    np.zeros(n),
                    integrality=np.ones(n),
                    bounds=Bounds(lo, hi),
                    constraints=LinearConstraint(xmat, lower, upper),
                    options={"time_limit": args.time_limit},
                )
                if result.x is None:
                    raise RuntimeError(
                        f"poly {p}: integer completion failed: {result.message}"
                    )
                candidate = np.rint(result.x).astype(np.int16)
                residual = design.apply(candidate, integer=True).reshape(-1) - u
                violating = np.flatnonzero(np.abs(residual) > NOISE_BOUND)
                print(
                    f"poly={p} round={rounds} active={len(active)} "
                    f"violations={len(violating)} max_residual={np.abs(residual).max():.0f}",
                    flush=True,
                )
                if not len(violating):
                    break
                active.update(violating.tolist())
            else:
                raise RuntimeError(f"poly {p}: cutting-plane limit reached")

        residual = design.apply(candidate, integer=True).reshape(-1) - u
        fields = [
            f"poly={p}",
            f"initial_violations={initial_violations}",
            f"final_violations={np.count_nonzero(np.abs(residual) > NOISE_BOUND)}",
            f"max_residual={np.abs(residual).max():.0f}",
        ]
        if truth is not None:
            fields += [
                f"exact={np.count_nonzero(candidate == truth[p])}/{n}",
                f"max_error={np.max(np.abs(candidate-truth[p])):.0f}",
            ]
        print(" ".join(fields), flush=True)
        completed.append(candidate)

    result = np.vstack(completed)
    if truth is not None:
        print(
            f"all_exact={np.count_nonzero(result == truth)}/{truth.size} "
            f"max_error={np.max(np.abs(result-truth)):.0f}",
            flush=True,
        )
    if args.output is not None:
        np.savez(args.output, integer=result)


if __name__ == "__main__":
    main()

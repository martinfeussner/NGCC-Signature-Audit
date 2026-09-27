#!/usr/bin/env python3
"""Solve public MORNING-ATLAS response-support inequalities.

The binary input is emitted by morning_faithful_constraints.  Secret data is
optional and used only to score an experiment; it never enters the solve.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, linprog, milp
from scipy.sparse import csr_matrix


HEADER = struct.Struct("<8sIIIIQQ")


def read_constraints(path: Path):
    data = path.read_bytes()
    magic, n, ell, kappa, pkbytes, signatures, count = HEADER.unpack_from(data)
    if magic.rstrip(b"\0") not in (b"ATLCON1", b"ATLSIM1"):
        raise ValueError("bad constraint magic")
    offset = HEADER.size + pkbytes
    dtype = np.dtype(
        [("poly", "u1"), ("sense", "i1"), ("bound", "<i2"), ("row", "i1", (n,))],
        align=False,
    )
    rows = np.frombuffer(data, dtype=dtype, count=count, offset=offset)
    if offset + count * dtype.itemsize != len(data):
        raise ValueError(
            f"size mismatch: header says {count} rows of {dtype.itemsize} bytes"
        )
    return n, ell, kappa, signatures, rows


def load_secret(path: Path | None, ell: int, n: int):
    if path is None:
        return None
    secret = np.loadtxt(path, dtype=np.int16)
    return secret.reshape(ell, n)


def system_for(rows, polynomial: int, n: int):
    selected = rows[rows["poly"] == polynomial]
    dense = selected["row"].astype(np.float64)
    sense = selected["sense"].astype(np.int8)
    bounds = selected["bound"].astype(np.float64)
    # scipy's linprog convention is A_ub x <= b_ub.
    signs = np.where(sense > 0, -1.0, 1.0)
    a_ub = csr_matrix(dense * signs[:, None])
    b_ub = bounds * signs
    return selected, a_ub, b_ub


def score(label: str, estimate: np.ndarray, truth: np.ndarray | None):
    fields = [f"{label}=OK", f"estimate_min={estimate.min():.4f}", f"estimate_max={estimate.max():.4f}"]
    if truth is not None:
        err = estimate - truth
        fields += [
            f"rmse={np.sqrt(np.mean(err * err)):.6f}",
            f"max_error={np.max(np.abs(err)):.6f}",
            f"rounded_exact={np.count_nonzero(np.rint(estimate) == truth)}/{truth.size}",
        ]
    print(" ".join(fields), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("constraints", type=Path)
    ap.add_argument("--secret", type=Path)
    ap.add_argument("--random-vertices", type=int, default=8)
    ap.add_argument("--milp", action="store_true")
    ap.add_argument("--intervals", action="store_true")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    n, ell, kappa, signatures, rows = read_constraints(args.constraints)
    truth = load_secret(args.secret, ell, n)
    print(
        f"signatures={signatures} constraints={len(rows)} n={n} l={ell} kappa={kappa}",
        flush=True,
    )
    rng = np.random.default_rng(0x41544C4153)
    all_estimates = []
    for p in range(ell):
        selected, a_ub, b_ub = system_for(rows, p, n)
        if truth is not None:
            vals = selected["row"].astype(np.int32) @ truth[p].astype(np.int32)
            violations = np.count_nonzero(
                np.where(selected["sense"] > 0, vals < selected["bound"], vals > selected["bound"])
            )
        else:
            violations = -1
        print(f"poly={p} rows={len(selected)} true_violations={violations}", flush=True)

        result = linprog(
            np.zeros(n), A_ub=a_ub, b_ub=b_ub, bounds=[(-16, 16)] * n, method="highs"
        )
        if not result.success:
            print(f"poly={p} continuous=FAIL status={result.status} {result.message}")
            continue
        score(f"poly={p} continuous", result.x, None if truth is None else truth[p])

        vertices = []
        for _ in range(args.random_vertices):
            objective = rng.normal(size=n)
            vertex = linprog(
                objective,
                A_ub=a_ub,
                b_ub=b_ub,
                bounds=[(-16, 16)] * n,
                method="highs",
            )
            if vertex.success:
                vertices.append(vertex.x)
        if vertices:
            mean_vertex = np.mean(vertices, axis=0)
            score(
                f"poly={p} vertex_mean[{len(vertices)}]",
                mean_vertex,
                None if truth is None else truth[p],
            )
            all_estimates.append(mean_vertex)

        if args.milp:
            constraint = LinearConstraint(a_ub, -np.inf, b_ub)
            integer = milp(
                np.zeros(n),
                integrality=np.ones(n),
                bounds=Bounds(-16 * np.ones(n), 16 * np.ones(n)),
                constraints=constraint,
                options={"time_limit": 60.0},
            )
            if integer.success:
                score(f"poly={p} integer", integer.x, None if truth is None else truth[p])
            else:
                print(f"poly={p} integer=FAIL status={integer.status} {integer.message}")

        if args.intervals:
            lo = np.empty(n)
            hi = np.empty(n)
            for j in range(n):
                objective = np.zeros(n)
                objective[j] = 1
                low = linprog(
                    objective, A_ub=a_ub, b_ub=b_ub,
                    bounds=[(-16, 16)] * n, method="highs"
                )
                high = linprog(
                    -objective, A_ub=a_ub, b_ub=b_ub,
                    bounds=[(-16, 16)] * n, method="highs"
                )
                lo[j] = low.fun if low.success else np.nan
                hi[j] = -high.fun if high.success else np.nan
            widths = hi - lo
            print(
                f"poly={p} intervals mean_width={np.nanmean(widths):.6f} "
                f"max_width={np.nanmax(widths):.6f} integer_singletons={np.count_nonzero(np.ceil(lo)==np.floor(hi))}/{n}",
                flush=True,
            )

    if truth is not None and len(all_estimates) == ell:
        estimate = np.vstack(all_estimates)
        score("all_vertex_mean", estimate, truth)
    if args.output is not None and len(all_estimates) == ell:
        estimate = np.vstack(all_estimates)
        np.savez(
            args.output,
            continuous=estimate,
            rounded=np.rint(estimate).astype(np.int16),
        )


if __name__ == "__main__":
    main()

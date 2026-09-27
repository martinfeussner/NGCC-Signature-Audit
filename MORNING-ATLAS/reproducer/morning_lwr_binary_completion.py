#!/usr/bin/env python3
"""Public global completion of a MORNING radial estimate with the LWR key.

Every secret coefficient is restricted to the floor/ceiling of the public
continuous estimate.  One MILP couples all six polynomials to the exact public
LWR relation and a public working set of response-support inequalities.  Every
incumbent is checked against the complete response transcript and violating
rows are added as cutting planes.  An optional secret is diagnostic only.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, csr_matrix, hstack, vstack

from morning_constraint_solve import read_constraints
from morning_lwr_milp import centered, read_lwr, rotation_rows


ETA = 16


def public_lwr_system(lwr_path: Path):
    n, k, ell, q, p, matrix, target = read_lwr(lwr_path)
    rr, cc, vv = rotation_rows(matrix, q)
    secret_matrix = coo_matrix(
        (vv, (rr, cc)), shape=(k * n, ell * n), dtype=np.float64
    ).tocsr()
    center = (32 * target).reshape(-1).astype(np.int64)
    return n, k, ell, q, p, secret_matrix, center


def response_matrix(records: np.ndarray, active: np.ndarray, n: int, nv: int):
    rr: list[int] = []
    cc: list[int] = []
    vv: list[float] = []
    lower = np.empty(len(active), dtype=np.float64)
    upper = np.empty(len(active), dtype=np.float64)
    for out_row, record_index in enumerate(active):
        record = records[int(record_index)]
        nz = np.flatnonzero(record["row"])
        rr.extend([out_row] * len(nz))
        cc.extend((int(record["poly"]) * n + nz).tolist())
        vv.extend(record["row"][nz].astype(np.float64).tolist())
        if record["sense"] > 0:
            lower[out_row] = float(record["bound"])
            upper[out_row] = np.inf
        else:
            lower[out_row] = -np.inf
            upper[out_row] = float(record["bound"])
    matrix = coo_matrix(
        (vv, (rr, cc)), shape=(len(active), nv), dtype=np.float64
    ).tocsr()
    return matrix, lower, upper


def full_response_violations(records: np.ndarray, candidate: np.ndarray):
    values = np.empty(len(records), dtype=np.int32)
    for polynomial in range(candidate.shape[0]):
        where = np.flatnonzero(records["poly"] == polynomial)
        values[where] = (
            records[where]["row"].astype(np.int32)
            @ candidate[polynomial].astype(np.int32)
        )
    violation = np.where(
        records["sense"] > 0,
        records["bound"].astype(np.int32) - values,
        values - records["bound"].astype(np.int32),
    )
    return violation


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("constraints", type=Path)
    parser.add_argument("estimate", type=Path)
    parser.add_argument("lwr", type=Path)
    parser.add_argument("--secret", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--working-rows", type=int, default=5000)
    parser.add_argument("--add-rows", type=int, default=5000)
    parser.add_argument("--time-limit", type=float, default=300.0)
    parser.add_argument("--max-cuts", type=int, default=4)
    args = parser.parse_args()

    n, ell, kappa, signatures, records = read_constraints(args.constraints)
    ln, k, lell, q, p, secret_matrix, center = public_lwr_system(args.lwr)
    if (ln, lell) != (n, ell):
        raise ValueError("constraint/LWR dimensions differ")
    estimate = np.load(args.estimate)["continuous"].astype(np.float64)
    if estimate.shape != (ell, n):
        raise ValueError("estimate shape mismatch")

    ns = ell * n
    ne = k * n
    nv = ns + ne
    lower_secret = np.maximum(-ETA, np.floor(estimate)).reshape(-1)
    upper_secret = np.minimum(ETA, np.ceil(estimate)).reshape(-1)

    positive = secret_matrix.maximum(0)
    negative = secret_matrix.minimum(0)
    raw_min = np.rint(
        positive @ lower_secret + negative @ upper_secret
    ).astype(np.int64)
    raw_max = np.rint(
        positive @ upper_secret + negative @ lower_secret
    ).astype(np.int64)
    quotient_lower = -np.floor_divide(
        -(raw_min - center - 15), q
    )
    quotient_upper = np.floor_divide(raw_max - center + 16, q)
    if np.any(quotient_lower > quotient_upper):
        raise ValueError("empty quotient bounds")

    quotient_columns = -q * csr_matrix(np.eye(ne, dtype=np.float64))
    lwr_matrix = hstack([secret_matrix, quotient_columns]).tocsr()
    lwr_lower = (center - 16).astype(np.float64)
    lwr_upper = (center + 15).astype(np.float64)

    active: set[int] = set()
    for polynomial in range(ell):
        selected = np.flatnonzero(records["poly"] == polynomial)
        rows = records[selected]["row"].astype(np.float64)
        senses = records[selected]["sense"].astype(np.float64)
        bounds = records[selected]["bound"].astype(np.float64)
        slack = senses * (rows @ estimate[polynomial] - bounds)
        take_count = min(args.working_rows, len(selected))
        take = np.argpartition(slack, take_count - 1)[:take_count]
        active.update(selected[take].tolist())

    objective = np.zeros(nv, dtype=np.float64)
    objective[:ns] = -estimate.reshape(-1)
    variable_bounds = Bounds(
        np.concatenate([lower_secret, quotient_lower]),
        np.concatenate([upper_secret, quotient_upper]),
    )
    truth = None
    if args.secret is not None:
        truth = np.loadtxt(args.secret, dtype=np.int16).reshape(ell, n)

    print(
        f"signatures={signatures} response_rows={len(records)} n={n} l={ell} "
        f"k={k} variables={nv} binary_secret_choices="
        f"{np.count_nonzero(lower_secret != upper_secret)} "
        f"time_limit={args.time_limit}",
        flush=True,
    )

    candidate = None
    started = time.monotonic()
    for cut in range(args.max_cuts):
        remaining = args.time_limit - (time.monotonic() - started)
        if remaining <= 0:
            break
        active_array = np.asarray(sorted(active), dtype=np.int64)
        response, response_lower, response_upper = response_matrix(
            records, active_array, n, nv
        )
        all_matrix = vstack([lwr_matrix, response]).tocsr()
        all_lower = np.concatenate([lwr_lower, response_lower])
        all_upper = np.concatenate([lwr_upper, response_upper])
        result = milp(
            objective,
            integrality=np.ones(nv),
            bounds=variable_bounds,
            constraints=LinearConstraint(all_matrix, all_lower, all_upper),
            options={
                "time_limit": remaining,
                "mip_rel_gap": 0.0,
                "presolve": True,
            },
        )
        if result.x is None:
            print(
                f"cut={cut} status={result.status} no_incumbent "
                f"message={result.message}",
                flush=True,
            )
            break
        candidate = np.rint(result.x[:ns]).astype(np.int16).reshape(ell, n)
        violation = full_response_violations(records, candidate)
        bad = np.flatnonzero(violation > 0)

        raw = np.rint(secret_matrix @ candidate.reshape(-1)).astype(np.int64)
        residual = centered(raw - center, q)
        lwr_valid = bool(np.all((residual >= -16) & (residual <= 15)))
        fields = [
            f"cut={cut}",
            f"status={result.status}",
            f"active={len(active)}",
            f"full_violations={len(bad)}",
            f"objective={estimate.reshape(-1) @ candidate.reshape(-1):.9f}",
            f"lwr_residual=[{residual.min()},{residual.max()}]",
            f"lwr_valid={str(lwr_valid).lower()}",
        ]
        if truth is not None:
            error = candidate.astype(np.int32) - truth.astype(np.int32)
            fields.extend(
                [
                    f"exact={np.count_nonzero(error == 0)}/{truth.size}",
                    f"max_error={np.max(np.abs(error))}",
                ]
            )
        print(" ".join(fields), flush=True)
        if len(bad) == 0 and lwr_valid:
            break
        if len(bad) == 0:
            raise RuntimeError("MILP incumbent violates the modeled LWR system")
        take_count = min(args.add_rows, len(bad))
        take = bad[np.argpartition(violation[bad], -take_count)[-take_count:]]
        old_size = len(active)
        active.update(take.tolist())
        if len(active) == old_size:
            raise RuntimeError("response cutting plane stalled")

    if candidate is None:
        raise RuntimeError("no global integer incumbent")
    violation = full_response_violations(records, candidate)
    if np.any(violation > 0):
        raise RuntimeError(
            f"global candidate violates {np.count_nonzero(violation > 0)} response rows"
        )
    raw = np.rint(secret_matrix @ candidate.reshape(-1)).astype(np.int64)
    residual = centered(raw - center, q)
    if not np.all((residual >= -16) & (residual <= 15)):
        raise RuntimeError("global candidate fails exact public LWR validation")
    if args.output is not None:
        np.savez(args.output, secret=candidate)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Try direct bounded-integer completion of a recovered MORNING full-t key.

This is a public attack attempt.  It models A*s = 32*t + e (mod 2^23),
s in [-16,16] and e in [-16,15], with optional public response-support
inequalities.  A secret file is optional and is used only for diagnostics.
"""

from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, vstack


LWR_HEADER = struct.Struct("<8sIIIII")
CON_HEADER = struct.Struct("<8sIIIIQQ")


def read_lwr(path: Path):
    data = path.read_bytes()
    magic, n, k, ell, q, p = LWR_HEADER.unpack_from(data)
    if magic.rstrip(b"\0") != b"ATLLWR1":
        raise ValueError("bad LWR file")
    off = LWR_HEADER.size
    amat = np.frombuffer(data, dtype="<u4", count=k * ell * n, offset=off)
    amat = amat.reshape(k, ell, n).astype(np.int64)
    off += k * ell * n * 4
    target = np.frombuffer(data, dtype="<u4", count=k * n, offset=off)
    return n, k, ell, q, p, amat, target.reshape(k, n).astype(np.int64)


def centered(values: np.ndarray, modulus: int) -> np.ndarray:
    values = np.remainder(values, modulus)
    return np.where(values > modulus // 2, values - modulus, values)


def rotation_rows(amat: np.ndarray, q: int):
    k, ell, n = amat.shape
    rows, cols, values = [], [], []
    ac = centered(amat, q)
    for out_poly in range(k):
        for out_coeff in range(n):
            row = out_poly * n + out_coeff
            for secret_poly in range(ell):
                a = ac[out_poly, secret_poly]
                for source in range(n):
                    index = out_coeff - source
                    sign = 1
                    if index < 0:
                        index += n
                        sign = -1
                    value = sign * int(a[index])
                    if value:
                        rows.append(row)
                        cols.append(secret_poly * n + source)
                        values.append(value)
    return rows, cols, values


def read_response_constraints(path: Path, n: int, ell: int):
    data = path.read_bytes()
    magic, cn, cell, kappa, pkbytes, signatures, count = CON_HEADER.unpack_from(data)
    if magic.rstrip(b"\0") != b"ATLCON1" or cn != n or cell != ell:
        raise ValueError("bad constraint file")
    off = CON_HEADER.size + pkbytes
    dtype = np.dtype(
        [("poly", "u1"), ("sense", "i1"), ("bound", "<i2"), ("row", "i1", (n,))]
    )
    records = np.frombuffer(data, dtype=dtype, count=count, offset=off)
    return signatures, records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lwr", type=Path)
    ap.add_argument("--constraints", type=Path)
    ap.add_argument("--secret", type=Path)
    ap.add_argument("--time-limit", type=float, default=300.0)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    n, k, ell, q, p, amat, target = read_lwr(args.lwr)
    ns = ell * n
    ne = k * n
    nv = ns + ne
    rows, cols, values = rotation_rows(amat, q)
    # One quotient variable per public LWR coefficient.
    for row in range(ne):
        rows.append(row)
        cols.append(ns + row)
        values.append(-q)
    lwr_matrix = coo_matrix((values, (rows, cols)), shape=(ne, nv)).tocsr()
    center = (32 * target).reshape(-1).astype(np.float64)
    matrices = [lwr_matrix]
    lowers = [center - 16]
    uppers = [center + 15]

    signatures = 0
    response_rows = 0
    records = None
    if args.constraints is not None:
        signatures, records = read_response_constraints(args.constraints, n, ell)
        rr, cc, vv = [], [], []
        for row_index, record in enumerate(records):
            nz = np.flatnonzero(record["row"])
            rr.extend([row_index] * len(nz))
            cc.extend((int(record["poly"]) * n + nz).tolist())
            vv.extend(record["row"][nz].astype(np.float64).tolist())
        response = coo_matrix((vv, (rr, cc)), shape=(len(records), nv)).tocsr()
        sense = records["sense"].astype(np.int8)
        bound = records["bound"].astype(np.float64)
        matrices.append(response)
        lowers.append(np.where(sense > 0, bound, -np.inf))
        uppers.append(np.where(sense < 0, bound, np.inf))
        response_rows = len(records)

    matrix = vstack(matrices).tocsr()
    lower = np.concatenate(lowers)
    upper = np.concatenate(uppers)
    # The centered A representation makes these quotient bounds very loose,
    # but finite bounds help presolve and safely contain every boxed secret.
    row_radius = np.asarray(abs(lwr_matrix[:, :ns]).sum(axis=1)).reshape(-1) * 16
    klo = np.floor((-row_radius - center - 16) / q) - 1
    khi = np.ceil((row_radius - center + 16) / q) + 1
    bounds = Bounds(
        np.concatenate([-16 * np.ones(ns), klo]),
        np.concatenate([16 * np.ones(ns), khi]),
    )
    print(
        f"n={n} k={k} l={ell} variables={nv} integer_variables={nv} "
        f"lwr_rows={ne} response_rows={response_rows} signatures={signatures} "
        f"nnz={matrix.nnz} time_limit={args.time_limit}",
        flush=True,
    )
    truth = None
    if args.secret is not None:
        truth = np.loadtxt(args.secret, dtype=np.int64).reshape(ell, n)
        raw = np.asarray(lwr_matrix[:, :ns] @ truth.reshape(-1)).reshape(-1)
        difference = centered(raw - center.astype(np.int64), q)
        quotient = (raw - center.astype(np.int64) - difference) // q
        quotient_in_bounds = np.count_nonzero((quotient >= klo) & (quotient <= khi))
        fields = [
            f"calibration_lwr_residual=[{difference.min()},{difference.max()}]",
            f"calibration_quotient_bounds={quotient_in_bounds}/{ne}",
        ]
        if records is not None:
            response_values = np.asarray(response[:, :ns] @ truth.reshape(-1)).reshape(-1)
            response_bad = np.count_nonzero(
                np.where(
                    records["sense"] > 0,
                    response_values < records["bound"],
                    response_values > records["bound"],
                )
            )
            fields.append(f"calibration_response_violations={response_bad}/{len(records)}")
        print(" ".join(fields), flush=True)
    started = time.monotonic()
    result = milp(
        np.zeros(nv),
        integrality=np.ones(nv),
        bounds=bounds,
        constraints=LinearConstraint(matrix, lower, upper),
        options={"time_limit": args.time_limit, "presolve": True},
    )
    elapsed = time.monotonic() - started
    print(
        f"status={result.status} success={result.success} elapsed={elapsed:.3f} "
        f"message={result.message}",
        flush=True,
    )
    if result.x is None:
        return
    candidate = np.rint(result.x[:ns]).astype(np.int16).reshape(ell, n)
    lhs = np.rint(lwr_matrix @ np.rint(result.x)).astype(np.int64)
    residual = lhs - center.astype(np.int64)
    print(
        f"candidate_range=[{candidate.min()},{candidate.max()}] "
        f"lwr_residual=[{residual.min()},{residual.max()}]",
        flush=True,
    )
    if truth is not None:
        error = candidate.astype(np.int32) - truth.astype(np.int32)
        print(
            f"exact={np.count_nonzero(error == 0)}/{ns} "
            f"rmse={np.sqrt(np.mean(error.astype(float) ** 2)):.6f} "
            f"max_error={np.max(np.abs(error))}",
            flush=True,
        )
    if args.output is not None:
        np.savez(args.output, secret=candidate)


if __name__ == "__main__":
    main()

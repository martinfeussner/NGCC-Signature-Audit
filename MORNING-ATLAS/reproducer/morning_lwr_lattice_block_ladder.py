#!/usr/bin/env python3
"""Public lattice completion of MORNING floor/ceiling secret boxes.

For each polynomial support in lexicographic order, fix the other five
polynomials to an independently response-feasible public candidate.  Map the
remaining floor/ceiling choices to a {-1,+1} vector and build a Kannan
embedding for a fixed, publicly selected subset of the exact LWR equations.
Any binary vector exposed by lattice reduction must satisfy every LWR
coefficient and every response-support inequality before it is accepted.

No secret-key material is accepted as input.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
from fpylll import BKZ, FPLLL, GSO, IntegerMatrix, LLL
from fpylll.algorithms.bkz2 import BKZReduction

from morning_constraint_solve import read_constraints
from morning_lwr_binary_completion import (
    full_response_violations,
    public_lwr_system,
)
from morning_lwr_milp import centered
from morning_lwr_reduced_block_ladder import select_lwr_rows


ETA = 16


def centered_scalar(value: int, modulus: int) -> int:
    value %= modulus
    if value > modulus // 2:
        value -= modulus
    return value


def candidate_from_row(
    row: np.ndarray,
    sample_count: int,
    variable_indices: np.ndarray,
    secret_scale: int,
    embedding_scale: int,
    fixed: np.ndarray,
    polynomial: int,
):
    if abs(int(row[-1])) != embedding_scale:
        return None
    # The desired embedded vector has final coordinate -embedding_scale.
    if row[-1] > 0:
        row = -row
    secret_part = row[
        sample_count : sample_count + len(variable_indices)
    ]
    if np.any(secret_part % secret_scale):
        return None
    signed = secret_part // secret_scale
    if np.any((signed != -1) & (signed != 1)):
        return None
    increments = ((signed + 1) // 2).astype(np.int16)
    candidate = fixed.copy()
    candidate[polynomial, variable_indices] += increments
    return candidate


def validate_candidate(
    candidate: np.ndarray,
    records: np.ndarray,
    secret_matrix,
    center: np.ndarray,
    q: int,
):
    response_bad = full_response_violations(records, candidate)
    raw = np.rint(secret_matrix @ candidate.reshape(-1)).astype(np.int64)
    residual = centered(raw - center, q)
    lwr_valid = bool(np.all((residual >= -16) & (residual <= 15)))
    return int(np.count_nonzero(response_bad > 0)), residual, lwr_valid


def inspect_basis(
    basis: IntegerMatrix,
    stage: str,
    polynomial: int,
    sample_count: int,
    variable_indices: np.ndarray,
    secret_scale: int,
    embedding_scale: int,
    fixed: np.ndarray,
    records: np.ndarray,
    secret_matrix,
    center: np.ndarray,
    q: int,
):
    binary_rows = 0
    for row_index in range(basis.nrows):
        row = np.fromiter(
            (int(basis[row_index, column]) for column in range(basis.ncols)),
            dtype=object,
            count=basis.ncols,
        )
        candidate = candidate_from_row(
            row,
            sample_count,
            variable_indices,
            secret_scale,
            embedding_scale,
            fixed,
            polynomial,
        )
        if candidate is None:
            continue
        binary_rows += 1
        response_violations, residual, lwr_valid = validate_candidate(
            candidate, records, secret_matrix, center, q
        )
        print(
            f"blocks=({polynomial},) stage={stage} row={row_index} "
            f"binary_embedding=true response_violations={response_violations} "
            f"lwr_residual=[{residual.min()},{residual.max()}] "
            f"lwr_valid={str(lwr_valid).lower()}",
            flush=True,
        )
        if response_violations == 0 and lwr_valid:
            return candidate, binary_rows
    print(
        f"blocks=({polynomial},) stage={stage} binary_embedding_rows={binary_rows}",
        flush=True,
    )
    return None, binary_rows


def build_embedding(
    polynomial: int,
    base: np.ndarray,
    estimate: np.ndarray,
    secret_matrix,
    center: np.ndarray,
    q: int,
    sample_count: int,
    secret_scale: int,
    embedding_scale: int,
):
    ell, n = base.shape
    lower_block = np.maximum(-ETA, np.floor(estimate[polynomial])).astype(np.int16)
    upper_block = np.minimum(ETA, np.ceil(estimate[polynomial])).astype(np.int16)
    variable_indices = np.flatnonzero(lower_block != upper_block)
    fixed = base.copy()
    fixed[polynomial] = lower_block
    raw_fixed = np.rint(secret_matrix @ fixed.reshape(-1)).astype(np.int64)
    block_start = polynomial * n
    variable_columns = block_start + variable_indices

    chosen = select_lwr_rows(sample_count, len(center))
    coefficients = np.rint(
        secret_matrix[chosen][:, variable_columns].toarray()
    ).astype(np.int64)
    b = center[chosen].astype(np.int64) - raw_fixed[chosen]
    doubled_modulus = 2 * q
    # If A*d - b = e (mod q) and u=2*d-1, then
    # A*u - (2*b-A*1) = 2*e (mod 2*q).
    target = 2 * b - coefficients.sum(axis=1)
    coefficients = np.vectorize(centered_scalar, otypes=[object])(
        coefficients, doubled_modulus
    )
    target = np.fromiter(
        (centered_scalar(int(value), doubled_modulus) for value in target),
        dtype=object,
        count=len(target),
    )

    variable_count = len(variable_indices)
    dimension = sample_count + variable_count + 1
    basis = IntegerMatrix(dimension, dimension)
    for row in range(sample_count):
        basis[row, row] = doubled_modulus
    for variable in range(variable_count):
        basis[sample_count + variable, sample_count + variable] = secret_scale
        for sample in range(sample_count):
            basis[sample_count + variable, sample] = int(
                coefficients[sample, variable]
            )
    final_row = dimension - 1
    for sample in range(sample_count):
        basis[final_row, sample] = int(target[sample])
    basis[final_row, final_row] = embedding_scale
    return basis, fixed, variable_indices


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("constraints", type=Path)
    parser.add_argument("estimate", type=Path)
    parser.add_argument("base_candidate", type=Path)
    parser.add_argument("lwr", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=96)
    parser.add_argument("--secret-scale", type=int, default=18)
    parser.add_argument("--embedding-scale", type=int, default=1)
    parser.add_argument(
        "--bkz-block-sizes",
        type=int,
        nargs="*",
        default=[10, 20, 30],
    )
    parser.add_argument("--bkz-loops", type=int, default=2)
    args = parser.parse_args()

    n, ell, kappa, signatures, records = read_constraints(args.constraints)
    ln, k, lell, q, p, secret_matrix, center = public_lwr_system(args.lwr)
    if (ln, lell) != (n, ell):
        raise ValueError("constraint/LWR dimensions differ")
    if args.samples > k * n:
        raise ValueError("too many LWR samples requested")
    estimate = np.load(args.estimate)["continuous"].astype(np.float64)
    base = np.load(args.base_candidate)["secret"].astype(np.int16)
    if estimate.shape != (ell, n) or base.shape != (ell, n):
        raise ValueError("candidate shape mismatch")
    if np.any(full_response_violations(records, base) > 0):
        raise ValueError("base candidate is not response feasible")

    print(
        f"signatures={signatures} response_rows={len(records)} n={n} l={ell} "
        f"k={k} samples={args.samples} secret_scale={args.secret_scale} "
        f"embedding_scale={args.embedding_scale} "
        f"bkz_block_sizes={args.bkz_block_sizes}",
        flush=True,
    )
    for polynomial in range(ell):
        basis, fixed, variable_indices = build_embedding(
            polynomial,
            base,
            estimate,
            secret_matrix,
            center,
            q,
            args.samples,
            args.secret_scale,
            args.embedding_scale,
        )
        started = time.monotonic()
        print(
            f"blocks=({polynomial},) dimension={basis.nrows} "
            f"binary_variables={len(variable_indices)} stage=lll_start",
            flush=True,
        )
        LLL.reduction(basis, delta=0.99, eta=0.501)
        print(
            f"blocks=({polynomial},) stage=lll_done "
            f"elapsed={time.monotonic()-started:.3f}",
            flush=True,
        )
        candidate, _ = inspect_basis(
            basis,
            "lll",
            polynomial,
            args.samples,
            variable_indices,
            args.secret_scale,
            args.embedding_scale,
            fixed,
            records,
            secret_matrix,
            center,
            q,
        )
        if candidate is not None:
            if args.output is not None:
                np.savez(
                    args.output,
                    secret=candidate,
                    blocks=np.asarray([polynomial], dtype=np.int16),
                    stage=np.asarray("lll"),
                )
            print(f"SUCCESS blocks=({polynomial},) stage=lll", flush=True)
            return

        # The embedding mixes a unit final coordinate with 2*q diagonal
        # coordinates.  The default double-precision BKZ wrapper can fail in
        # Babai reduction on this scale separation, so use an MPFR GSO.
        FPLLL.set_precision(256)
        gso = GSO.Mat(basis, float_type="mpfr")
        gso.update_gso()
        bkz = BKZReduction(gso)
        for block_size in args.bkz_block_sizes:
            print(
                f"blocks=({polynomial},) stage=bkz{block_size}_start",
                flush=True,
            )
            parameters = BKZ.Param(
                block_size=block_size,
                max_loops=args.bkz_loops,
                flags=BKZ.MAX_LOOPS,
            )
            bkz(parameters)
            print(
                f"blocks=({polynomial},) stage=bkz{block_size}_done "
                f"elapsed={time.monotonic()-started:.3f}",
                flush=True,
            )
            candidate, _ = inspect_basis(
                basis,
                f"bkz{block_size}",
                polynomial,
                args.samples,
                variable_indices,
                args.secret_scale,
                args.embedding_scale,
                fixed,
                records,
                secret_matrix,
                center,
                q,
            )
            if candidate is not None:
                if args.output is not None:
                    np.savez(
                        args.output,
                        secret=candidate,
                        blocks=np.asarray([polynomial], dtype=np.int16),
                        stage=np.asarray(f"bkz{block_size}"),
                    )
                print(
                    f"SUCCESS blocks=({polynomial},) stage=bkz{block_size}",
                    flush=True,
                )
                return
    raise RuntimeError("lattice block ladder found no public candidate")


if __name__ == "__main__":
    main()

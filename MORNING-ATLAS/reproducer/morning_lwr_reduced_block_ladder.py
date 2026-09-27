#!/usr/bin/env python3
"""Reduced deterministic public block ladder for MORNING LWR completion.

Starting from an independently response-feasible integer candidate, try every
polynomial support in lexicographic order.  On a support, eliminate all fixed
secret coefficients, express each remaining floor/ceiling choice as a binary
increment, and add public LWR rows in deterministic batches.  Every incumbent
is checked against all LWR rows and every response-support inequality.

The secret key is never an input to this program.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, csr_matrix, hstack, vstack

from morning_constraint_solve import read_constraints
from morning_lwr_binary_completion import (
    full_response_violations,
    public_lwr_system,
)
from morning_lwr_milp import centered


ETA = 16


def select_lwr_rows(count: int, total: int) -> np.ndarray:
    """Return a fixed prefix of a public interleaving of the LWR rows."""
    # The LWR rows are laid out as output_polynomial * n + coefficient.
    # Bit reversal spreads a short prefix over coefficients, while cycling the
    # output polynomial prevents the first batch from depending on one row of A.
    n = 128
    k = total // n
    order: list[int] = []
    for coefficient_index in range(n):
        reversed_index = int(f"{coefficient_index:07b}"[::-1], 2)
        for output_polynomial in range(k):
            order.append(output_polynomial * n + reversed_index)
    return np.asarray(order[:count], dtype=np.int64)


def response_constraints(
    records: np.ndarray,
    indices: np.ndarray,
    polynomial: int,
    base_block: np.ndarray,
    variable_indices: np.ndarray,
    variable_count: int,
    quotient_count: int,
):
    selected = records[indices]
    rows = selected["row"].astype(np.int64)
    constants = rows @ base_block.astype(np.int64)
    values = rows[:, variable_indices].astype(np.float64)
    matrix = hstack(
        [csr_matrix(values), csr_matrix((len(indices), quotient_count))]
    ).tocsr()
    bounds = selected["bound"].astype(np.float64) - constants
    senses = selected["sense"].astype(np.int8)
    lower = np.where(senses > 0, bounds, -np.inf)
    upper = np.where(senses < 0, bounds, np.inf)
    return matrix, lower, upper


def solve_support(
    polynomial: int,
    records: np.ndarray,
    base: np.ndarray,
    estimate: np.ndarray,
    secret_matrix: csr_matrix,
    center: np.ndarray,
    q: int,
    response_working_rows: int,
    response_add_rows: int,
    initial_lwr_rows: int,
    lwr_add_rows: int,
    max_rounds: int,
    time_limit: float,
):
    ell, n = base.shape
    ne = len(center)
    lower_block = np.maximum(-ETA, np.floor(estimate[polynomial])).astype(np.int16)
    upper_block = np.minimum(ETA, np.ceil(estimate[polynomial])).astype(np.int16)
    variable_indices = np.flatnonzero(lower_block != upper_block)
    variable_count = len(variable_indices)

    fixed = base.copy()
    fixed[polynomial] = lower_block
    raw_fixed = np.rint(secret_matrix @ fixed.reshape(-1)).astype(np.int64)
    block_start = polynomial * n
    variable_columns = block_start + variable_indices
    coefficients = secret_matrix[:, variable_columns].tocsr()
    target = center.astype(np.int64) - raw_fixed

    selected_records = np.flatnonzero(records["poly"] == polynomial)
    selected_rows = records[selected_records]["row"].astype(np.int64)
    selected_senses = records[selected_records]["sense"].astype(np.int64)
    selected_bounds = records[selected_records]["bound"].astype(np.int64)
    response_slack = selected_senses * (
        selected_rows @ estimate[polynomial] - selected_bounds
    )
    take_count = min(response_working_rows, len(selected_records))
    take = np.argpartition(response_slack, take_count - 1)[:take_count]
    active_response: set[int] = set(selected_records[take].tolist())

    initial_count = min(initial_lwr_rows, ne)
    active_lwr: set[int] = set(select_lwr_rows(initial_count, ne).tolist())
    objective_secret = -estimate[polynomial, variable_indices].astype(np.float64)
    started = time.monotonic()

    for round_index in range(max_rounds):
        remaining = time_limit - (time.monotonic() - started)
        if remaining <= 0:
            print(
                f"blocks=({polynomial},) round={round_index} outer_time_limit "
                f"elapsed={time.monotonic()-started:.3f}",
                flush=True,
            )
            return None

        lwr_indices = np.asarray(sorted(active_lwr), dtype=np.int64)
        lwr_coefficients = coefficients[lwr_indices].tocsr()
        positive = lwr_coefficients.maximum(0)
        negative = lwr_coefficients.minimum(0)
        raw_min = np.rint(negative @ np.ones(variable_count)).astype(np.int64)
        raw_max = np.rint(positive @ np.ones(variable_count)).astype(np.int64)
        active_target = target[lwr_indices]
        quotient_lower = -np.floor_divide(
            -(raw_min - active_target - 15), q
        )
        quotient_upper = np.floor_divide(
            raw_max - active_target + 16, q
        )
        if np.any(quotient_lower > quotient_upper):
            print(
                f"blocks=({polynomial},) round={round_index} empty_quotient_bounds",
                flush=True,
            )
            return None

        quotient_count = len(lwr_indices)
        quotient_columns = -q * csr_matrix(
            np.eye(quotient_count, dtype=np.float64)
        )
        lwr_matrix = hstack([lwr_coefficients, quotient_columns]).tocsr()
        lwr_lower = (active_target - 16).astype(np.float64)
        lwr_upper = (active_target + 15).astype(np.float64)

        response_indices = np.asarray(sorted(active_response), dtype=np.int64)
        response_matrix, response_lower, response_upper = response_constraints(
            records,
            response_indices,
            polynomial,
            lower_block,
            variable_indices,
            variable_count,
            quotient_count,
        )
        matrix = vstack([lwr_matrix, response_matrix]).tocsr()
        lower = np.concatenate([lwr_lower, response_lower])
        upper = np.concatenate([lwr_upper, response_upper])
        objective = np.concatenate(
            [objective_secret, np.zeros(quotient_count, dtype=np.float64)]
        )
        variable_lower = np.concatenate(
            [np.zeros(variable_count), quotient_lower.astype(np.float64)]
        )
        variable_upper = np.concatenate(
            [np.ones(variable_count), quotient_upper.astype(np.float64)]
        )

        result = milp(
            objective,
            integrality=np.ones(variable_count + quotient_count),
            bounds=Bounds(variable_lower, variable_upper),
            constraints=LinearConstraint(matrix, lower, upper),
            options={
                "time_limit": remaining,
                "mip_rel_gap": 0.0,
                "presolve": True,
            },
        )
        elapsed = time.monotonic() - started
        if result.x is None:
            print(
                f"blocks=({polynomial},) round={round_index} status={result.status} "
                f"no_incumbent lwr_rows={len(active_lwr)} "
                f"response_rows={len(active_response)} elapsed={elapsed:.3f}",
                flush=True,
            )
            return None

        candidate = fixed.copy()
        increments = np.rint(result.x[:variable_count]).astype(np.int16)
        candidate[polynomial, variable_indices] += increments

        response_violation = full_response_violations(records, candidate)
        response_bad = np.flatnonzero(response_violation > 0)
        raw = np.rint(secret_matrix @ candidate.reshape(-1)).astype(np.int64)
        residual = centered(raw - center, q)
        lwr_excess = np.maximum(-16 - residual, residual - 15)
        lwr_bad = np.flatnonzero(lwr_excess > 0)
        print(
            f"blocks=({polynomial},) round={round_index} status={result.status} "
            f"lwr_rows={len(active_lwr)} response_rows={len(active_response)} "
            f"full_lwr_violations={len(lwr_bad)} "
            f"full_response_violations={len(response_bad)} "
            f"elapsed={elapsed:.3f}",
            flush=True,
        )
        if len(lwr_bad) == 0 and len(response_bad) == 0:
            return candidate

        old_lwr = len(active_lwr)
        if len(lwr_bad):
            candidates_to_add = lwr_bad[~np.isin(lwr_bad, lwr_indices)]
            if len(candidates_to_add):
                add_count = min(lwr_add_rows, len(candidates_to_add))
                chosen = candidates_to_add[
                    np.argpartition(
                        lwr_excess[candidates_to_add], -add_count
                    )[-add_count:]
                ]
                active_lwr.update(chosen.tolist())

        old_response = len(active_response)
        if len(response_bad):
            candidates_to_add = response_bad[
                ~np.isin(response_bad, response_indices)
            ]
            if len(candidates_to_add):
                add_count = min(response_add_rows, len(candidates_to_add))
                chosen = candidates_to_add[
                    np.argpartition(
                        response_violation[candidates_to_add], -add_count
                    )[-add_count:]
                ]
                active_response.update(chosen.tolist())
        if len(active_lwr) == old_lwr and len(active_response) == old_response:
            raise RuntimeError("reduced block cutting-plane loop stalled")

    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("constraints", type=Path)
    parser.add_argument("estimate", type=Path)
    parser.add_argument("base_candidate", type=Path)
    parser.add_argument("lwr", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--response-working-rows", type=int, default=5000)
    parser.add_argument("--response-add-rows", type=int, default=5000)
    parser.add_argument("--initial-lwr-rows", type=int, default=12)
    parser.add_argument("--lwr-add-rows", type=int, default=12)
    parser.add_argument("--max-rounds", type=int, default=8)
    parser.add_argument("--time-limit", type=float, default=120.0)
    args = parser.parse_args()

    n, ell, kappa, signatures, records = read_constraints(args.constraints)
    ln, k, lell, q, p, secret_matrix, center = public_lwr_system(args.lwr)
    if (ln, lell) != (n, ell):
        raise ValueError("constraint/LWR dimensions differ")
    estimate = np.load(args.estimate)["continuous"].astype(np.float64)
    base = np.load(args.base_candidate)["secret"].astype(np.int16)
    if estimate.shape != (ell, n) or base.shape != (ell, n):
        raise ValueError("candidate shape mismatch")
    base_bad = full_response_violations(records, base)
    if np.any(base_bad > 0):
        raise ValueError("base candidate is not response feasible")

    print(
        f"signatures={signatures} response_rows={len(records)} n={n} l={ell} "
        f"k={k} initial_lwr_rows={args.initial_lwr_rows} "
        f"per_support_time={args.time_limit}",
        flush=True,
    )
    for polynomial in range(ell):
        candidate = solve_support(
            polynomial,
            records,
            base,
            estimate,
            secret_matrix,
            center,
            q,
            args.response_working_rows,
            args.response_add_rows,
            args.initial_lwr_rows,
            args.lwr_add_rows,
            args.max_rounds,
            args.time_limit,
        )
        if candidate is not None:
            if args.output is not None:
                np.savez(
                    args.output,
                    secret=candidate,
                    blocks=np.asarray([polynomial], dtype=np.int16),
                )
            print(f"SUCCESS blocks=({polynomial},)", flush=True)
            return
    raise RuntimeError("reduced block ladder found no public candidate")


if __name__ == "__main__":
    main()

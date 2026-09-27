#!/usr/bin/python3
"""Try DARTS public-key completion as a partial-information lattice CVP.

The public leakage score supplies guesses for s0 and s1.  Freezing confident
coordinates turns

    A0*s0 + A1*s1 + e = ((q+1)/2, 0, ...),

into a closest-vector problem for the corrections at selected coordinates and
the ternary error polynomial e.  True labels are optional and are used only to
assess diagnostic controls or to construct an explicitly labelled support
test; the normal attack mode selects coordinates solely by public posterior
confidence.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import struct
import time

import numpy as np
from fpylll import (BKZ, CVP, Enumeration, EvaluatorStrategy, GSO,
                    IntegerMatrix, LLL)
from fpylll.fplll.enumeration import EnumerationError

N = 512
Q = 130817
HALF_Q = 65409
POLYS = 2
PK_BYTES = 1120
SCORE_OFFSET = 24 + PK_BYTES
PRIORS = np.array([0.15, 0.70, 0.15])
DEFAULT_SIGMAS = np.array([0.0140, 0.0083])


def load_score(path: Path) -> tuple[int, np.ndarray]:
    raw = path.read_bytes()
    magic, n, polys, signatures = struct.unpack_from("<8sIIQ", raw)
    if magic.rstrip(b"\0") != b"DARTS02" or n != N or polys != POLYS:
        raise ValueError("invalid DARTS score")
    expected = SCORE_OFFSET + POLYS * N * 8
    if len(raw) != expected:
        raise ValueError(f"invalid score length {len(raw)} != {expected}")
    theta = np.frombuffer(raw, dtype="<f8", offset=SCORE_OFFSET).copy()
    return signatures, theta.reshape(POLYS, N)


def public_initial_means(values: np.ndarray) -> np.ndarray:
    """Initialize ordered class means using only scores and the public prior."""
    ordered = np.sort(values, kind="stable")
    tail = int(round(float(PRIORS[0]) * N))
    return np.array([
        ordered[-tail:].mean(),
        ordered[tail:-tail].mean(),
        ordered[:tail].mean(),
    ])


def fit_public_scales(theta: np.ndarray) -> np.ndarray:
    """Fit one shared component width per polynomial from public scores."""
    scales = np.empty(POLYS)
    for p in range(POLYS):
        means = public_initial_means(theta[p])
        sigma = float(np.std(theta[p]))
        for _ in range(500):
            lp = (
                np.log(PRIORS)[None, :]
                - np.log(sigma)
                - 0.5 * ((theta[p, :, None] - means[None, :]) / sigma) ** 2
            )
            lp -= lp.max(axis=1, keepdims=True)
            resp = np.exp(lp)
            resp /= resp.sum(axis=1, keepdims=True)
            masses = resp.sum(axis=0)
            new_means = (
                (resp * theta[p, :, None]).sum(axis=0) / masses
            )
            new_sigma = float(np.sqrt(
                (resp * (theta[p, :, None] - new_means[None, :]) ** 2).sum()
                / N
            ))
            change = max(
                float(np.max(np.abs(new_means - means))),
                abs(new_sigma - sigma),
            )
            means, sigma = new_means, new_sigma
            if change < 1e-13:
                break
        scales[p] = sigma
    return scales


def classify(theta: np.ndarray,
             widths: np.ndarray | None = None
             ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if widths is None:
        widths = DEFAULT_SIGMAS
    widths = np.asarray(widths, dtype=float)
    if widths.shape != (POLYS,) or np.any(widths <= 0):
        raise ValueError("classifier widths must be two positive values")
    # The first polynomial has the measured fixed component; the second
    # continues to scale statistically at the current checkpoint.
    sigmas = tuple(np.full(3, widths[p]) for p in range(POLYS))
    guess = np.empty((POLYS, N), dtype=np.int64)
    confidence = np.empty((POLYS, N))
    means_out = np.empty((POLYS, 3))
    for p in range(POLYS):
        means = public_initial_means(theta[p])
        sigma = sigmas[p]
        for _ in range(100):
            lp = (
                np.log(PRIORS)[None, :]
                - np.log(sigma)[None, :]
                - 0.5 * ((theta[p, :, None] - means[None, :]) /
                         sigma[None, :]) ** 2
            )
            lp -= lp.max(axis=1, keepdims=True)
            resp = np.exp(lp)
            resp /= resp.sum(axis=1, keepdims=True)
            means = (resp * theta[p, :, None]).sum(axis=0) / resp.sum(axis=0)
        lp = (
            np.log(PRIORS)[None, :]
            - np.log(sigma)[None, :]
            - 0.5 * ((theta[p, :, None] - means[None, :]) /
                     sigma[None, :]) ** 2
        )
        # Stable ordering makes exact likelihood ties deterministic: after
        # sorting by (-1, 0, +1), selecting the last entry prefers +1.
        order = np.argsort(lp, axis=1, kind="stable")
        guess[p] = order[:, -1] - 1
        confidence[p] = (
            lp[np.arange(N), order[:, -1]] - lp[np.arange(N), order[:, -2]]
        )
        means_out[p] = means
    return guess, confidence, means_out


def negacyclic_matrix(a: np.ndarray) -> np.ndarray:
    rows = np.arange(N)[:, None]
    cols = np.arange(N)[None, :]
    idx = (rows - cols) % N
    signs = np.where(rows >= cols, 1, -1)
    return (signs * a[idx]) % Q


def load_matrix(path: Path) -> np.ndarray:
    values = np.loadtxt(path, dtype=np.int64)
    if values.shape != (POLYS * N, 3):
        raise ValueError("invalid public-matrix dump")
    if not np.array_equal(values[:, 0], np.repeat(np.arange(POLYS), N)):
        raise ValueError("invalid polynomial indices")
    if not np.array_equal(values[:, 1], np.tile(np.arange(N), POLYS)):
        raise ValueError("invalid coefficient indices")
    return values[:, 2].reshape(POLYS, N) % Q


def product(matrix: np.ndarray, secret: np.ndarray) -> np.ndarray:
    out = np.zeros(N, dtype=np.int64)
    for p in range(POLYS):
        out += negacyclic_matrix(matrix[p]) @ secret[p]
    return out % Q


def assess_candidate(candidate: np.ndarray, matrix: np.ndarray,
                     truth: np.ndarray | None) -> tuple[bool, np.ndarray]:
    target = np.zeros(N, dtype=np.int64)
    target[0] = HALF_Q
    e = (target - product(matrix, candidate)) % Q
    e = np.where(e > Q // 2, e - Q, e)
    valid = bool(np.isin(e, (-1, 0, 1)).all() and
                 np.isin(candidate, (-1, 0, 1)).all())
    if truth is not None:
        print(
            f"candidate_s_correct={np.count_nonzero(candidate == truth[:POLYS])}/"
            f"{POLYS*N} candidate_e_correct="
            f"{np.count_nonzero(e == truth[POLYS])}/{N}"
        )
    return valid, e


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("score", type=Path)
    ap.add_argument("matrix", type=Path)
    ap.add_argument("--labels", type=Path)
    ap.add_argument("--u0", type=int, default=448)
    ap.add_argument("--u1", type=int, default=16)
    ap.add_argument("--support0", type=Path)
    ap.add_argument("--support1", type=Path)
    ap.add_argument("--diagnostic-error-support", action="store_true")
    ap.add_argument("--d-weight", type=int, default=2)
    ap.add_argument("--e-weight", type=int, default=1)
    ap.add_argument("--embedding", type=int, default=20)
    ap.add_argument("--tail0-weight-start", type=int, default=-1)
    ap.add_argument("--tail0-weight", type=int, default=1)
    ap.add_argument("--q-first", action="store_true")
    ap.add_argument(
        "--equations", type=int, default=128,
        help="number of public-key coefficients used inside the lattice",
    )
    ap.add_argument("--bkz", type=int, default=0)
    ap.add_argument("--bkz-loops", type=int, default=1)
    ap.add_argument("--lll-delta", type=float, default=0.99)
    ap.add_argument(
        "--lll-method",
        choices=("wrapper", "proved", "heuristic", "fast"),
        default="wrapper",
    )
    ap.add_argument(
        "--float-type",
        choices=("double", "long double", "dpe", "dd", "qd", "mpfr"),
        help="floating-point backend for LLL, BKZ, and enumeration",
    )
    ap.add_argument(
        "--precision", type=int, default=0,
        help="MPFR precision in bits (zero selects the fplll default)",
    )
    ap.add_argument("--output-secret", type=Path)
    ap.add_argument("--basis-input", type=Path)
    ap.add_argument("--basis-output", type=Path)
    ap.add_argument("--skip-lll", action="store_true")
    ap.add_argument("--skip-babai", action="store_true")
    ap.add_argument("--enumerate-bound", type=float, default=0.0)
    ap.add_argument("--enumerate-first", action="store_true")
    args = ap.parse_args()

    signatures, theta = load_score(args.score)
    public_matrix = load_matrix(args.matrix)
    guess, confidence, means = classify(theta)
    truth = None
    if args.labels is not None:
        labels = np.loadtxt(args.labels, dtype=np.int64)
        if labels.shape != (3 * N,) or not np.isin(labels, (-1, 0, 1)).all():
            raise ValueError("invalid labels")
        truth = labels.reshape(3, N)
    print(
        f"signatures={signatures} means0={means[0].tolist()} "
        f"means1={means[1].tolist()} public_counts="
        f"{[int(np.count_nonzero(guess == v)) for v in (-1,0,1)]}"
    )
    if truth is not None:
        print(f"public_correct={np.count_nonzero(guess == truth[:POLYS])}/{POLYS*N}")

    if args.diagnostic_error_support:
        if truth is None:
            raise ValueError("diagnostic error support requires --labels")
        chosen = [np.flatnonzero(guess[p] != truth[p]) for p in range(POLYS)]
    else:
        chosen = [
            np.argsort(confidence[0], kind="stable")[: args.u0],
            np.argsort(confidence[1], kind="stable")[: args.u1],
        ]
        for p, support_path in enumerate((args.support0, args.support1)):
            if support_path is None:
                continue
            support = np.atleast_1d(np.loadtxt(support_path, dtype=np.int64))
            if (support.ndim != 1 or len(np.unique(support)) != len(support) or
                    np.any(support < 0) or np.any(support >= N)):
                raise ValueError(f"invalid support file: {support_path}")
            # Preserve public confidence order so optional rank weights retain
            # their stated meaning.
            chosen[p] = support[
                np.argsort(confidence[p, support], kind="stable")
            ]
    variables = [(p, int(i)) for p in range(POLYS) for i in chosen[p]]
    u = len(variables)
    print(f"unknowns={u} support_sizes={len(chosen[0])},{len(chosen[1])}")
    if truth is not None:
        covered = sum(guess[p, i] != truth[p, i] for p, i in variables)
        total_errors = int(np.count_nonzero(guess != truth[:POLYS]))
        print(f"diagnostic_errors_covered={covered}/{total_errors}")

    if args.equations < 1 or args.equations > N:
        raise ValueError("--equations must lie in 1..512")
    # A subset is enough to identify a candidate: every additional wrong
    # coefficient independently has only about 3/q chance to look ternary.
    # Keeping the other equations for final validation greatly lowers the
    # reduction dimension.
    equation_indices = np.arange(args.equations)
    conv = [negacyclic_matrix(public_matrix[p]) for p in range(POLYS)]
    columns_full = np.column_stack([conv[p][:, i] for p, i in variables])
    columns = columns_full[equation_indices]
    rhs_full = np.zeros(N, dtype=np.int64)
    rhs_full[0] = HALF_Q
    rhs_full = (rhs_full - product(public_matrix, guess)) % Q
    rhs = rhs_full[equation_indices]

    if truth is not None:
        delta = np.array([truth[p, i] - guess[p, i] for p, i in variables])
        relation_e = (rhs - columns @ delta) % Q
        relation_e = np.where(relation_e > Q // 2, relation_e - Q, relation_e)
        print(
            f"diagnostic_target_relation="
            f"{'OK' if np.array_equal(relation_e, truth[2, equation_indices]) else 'FAILED'} "
            f"delta_norm={np.linalg.norm(delta):.6f} "
            f"e_norm={np.linalg.norm(truth[2]):.6f}"
        )

    equations = len(equation_indices)
    dim = u + equations + 1
    basis = IntegerMatrix(dim, dim)
    dw, ew, embed = args.d_weight, args.e_weight, args.embedding
    dweights = np.full(u, dw, dtype=np.int64)
    if 0 <= args.tail0_weight_start < len(chosen[0]):
        dweights[args.tail0_weight_start : len(chosen[0])] *= args.tail0_weight
    if args.q_first:
        for i in range(equations):
            basis[i, u + i] = ew * Q
        for j in range(u):
            basis[equations + j, j] = int(dweights[j])
            for i in range(equations):
                basis[equations + j, u + i] = ew * int(columns[i, j])
    else:
        for j in range(u):
            basis[j, j] = int(dweights[j])
            for i in range(equations):
                basis[j, u + i] = ew * int(columns[i, j])
        for i in range(equations):
            basis[u + i, u + i] = ew * Q
    for i in range(equations):
        basis[dim - 1, u + i] = ew * int(rhs[i])
    basis[dim - 1, dim - 1] = embed
    if args.basis_input is not None:
        loaded_basis = IntegerMatrix.from_file(str(args.basis_input))
        if loaded_basis.nrows != dim or loaded_basis.ncols != dim:
            raise ValueError(
                f"basis input has shape {loaded_basis.nrows}x"
                f"{loaded_basis.ncols}, expected {dim}x{dim}"
            )
        basis = loaded_basis

    started = time.monotonic()
    print(
        f"lll_start dimension={dim} weights={dw},{ew} embedding={embed} "
        f"tail0_weight={args.tail0_weight_start},{args.tail0_weight} "
        f"q_first={args.q_first}",
        flush=True,
    )
    reduction_options = {}
    if args.float_type is not None:
        reduction_options["float_type"] = args.float_type
    if args.precision:
        reduction_options["precision"] = args.precision
    if not args.skip_lll:
        LLL.reduction(
            basis,
            delta=args.lll_delta,
            eta=0.501,
            method=args.lll_method,
            **reduction_options,
        )
        print(f"lll_done wall={time.monotonic()-started:.3f}", flush=True)
    if args.bkz:
        par = BKZ.Param(block_size=args.bkz, max_loops=args.bkz_loops)
        BKZ.reduction(basis, par, **reduction_options)
        print(f"bkz_done block={args.bkz} wall={time.monotonic()-started:.3f}", flush=True)
    if args.basis_output is not None:
        args.basis_output.write_text(str(basis) + "\n")
        print(f"basis_output={args.basis_output}", flush=True)

    candidates = 0

    def try_vector(vector: list[int] | tuple[int, ...], source: str) -> bool:
        nonlocal candidates
        last = int(vector[dim - 1])
        if abs(last) != embed:
            return False
        sign = -1 if last == embed else 1
        raw = np.array([int(vector[j]) for j in range(u)], dtype=np.int64)
        if np.any(raw % dweights):
            return False
        delta = sign * raw // dweights
        candidate = guess.copy()
        for value, (p, i) in zip(delta, variables):
            candidate[p, i] += value
        candidates += 1
        valid, recovered_e = assess_candidate(candidate, public_matrix, truth)
        print(
            f"embedding_candidate={source} delta_max={np.max(np.abs(delta))} "
            f"delta_nonzero={np.count_nonzero(delta)} valid={valid}"
        )
        if valid:
            if args.output_secret is not None:
                complete = np.concatenate((candidate.ravel(), recovered_e))
                args.output_secret.write_text(
                    "".join(f"{int(v)}\n" for v in complete)
                )
                print(f"secret_output={args.output_secret}")
            print("completion=RECOVERED")
            return True
        return False

    for row in range(dim):
        vector = [int(basis[row, j]) for j in range(dim)]
        if try_vector(vector, f"row:{row}"):
            return

    if args.enumerate_bound > 0:
        enum_started = time.monotonic()
        gso_options = {"update": True}
        if args.float_type is not None:
            gso_options["float_type"] = args.float_type
        gso = GSO.Mat(basis, **gso_options)
        enumeration = Enumeration(
            gso,
            nr_solutions=1,
            strategy=(EvaluatorStrategy.FIRST_N_SOLUTIONS
                      if args.enumerate_first
                      else EvaluatorStrategy.BEST_N_SOLUTIONS),
        )
        print(f"enumeration_start bound={args.enumerate_bound}", flush=True)
        try:
            solutions = enumeration.enumerate(
                0, dim, args.enumerate_bound, 0
            )
        except EnumerationError:
            solutions = []
        print(
            f"enumeration_done solutions={len(solutions)} "
            f"wall={time.monotonic()-enum_started:.3f}",
            flush=True,
        )
        for distance, coefficients in solutions:
            rounded = [int(round(x)) for x in coefficients]
            vector = basis.multiply_left(rounded)
            if try_vector(vector, f"enumeration:{distance:.6f}"):
                return

    # Babai on the reduced non-embedding sublattice is another inexpensive
    # decoding view.  Remove the embedding row/column after reduction by
    # rebuilding the original CVP basis and reducing it independently.
    if args.skip_babai:
        print(f"completion=FAILED embedding_candidates={candidates}")
        return
    cvp_dim = u + equations
    cvp_basis = IntegerMatrix(cvp_dim, cvp_dim)
    if args.q_first:
        for i in range(equations):
            cvp_basis[i, u + i] = ew * Q
        for j in range(u):
            cvp_basis[equations + j, j] = int(dweights[j])
            for i in range(equations):
                cvp_basis[equations + j, u + i] = ew * int(columns[i, j])
    else:
        for j in range(u):
            cvp_basis[j, j] = int(dweights[j])
            for i in range(equations):
                cvp_basis[j, u + i] = ew * int(columns[i, j])
        for i in range(equations):
            cvp_basis[u + i, u + i] = ew * Q
    LLL.reduction(
        cvp_basis,
        delta=args.lll_delta,
        eta=0.501,
        method=args.lll_method,
        **reduction_options,
    )
    target = [0] * u + [ew * int(v) for v in rhs]
    closest = CVP.babai(cvp_basis, target)
    raw = np.array(closest[:u], dtype=np.int64)
    if np.all(raw % dweights == 0):
        delta = raw // dweights
        candidate = guess.copy()
        for value, (p, i) in zip(delta, variables):
            candidate[p, i] += value
        valid, recovered_e = assess_candidate(candidate, public_matrix, truth)
        print(
            f"babai_candidate delta_max={np.max(np.abs(delta))} "
            f"delta_nonzero={np.count_nonzero(delta)} valid={valid}"
        )
        if valid:
            if args.output_secret is not None:
                complete = np.concatenate((candidate.ravel(), recovered_e))
                args.output_secret.write_text(
                    "".join(f"{int(v)}\n" for v in complete)
                )
                print(f"secret_output={args.output_secret}")
            print("completion=RECOVERED")
            return
    print(f"completion=FAILED embedding_candidates={candidates}")


if __name__ == "__main__":
    main()

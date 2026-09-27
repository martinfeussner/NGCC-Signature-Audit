#!/usr/bin/env python3
"""Recover DARTS corrections with a binary-choice Kannan embedding.

For every selected coefficient, the public score supplies a best label and a
runner-up label.  Writing the correction as a*x with x in {0,1}, center x as
y=1-2x.  Valid binary choices therefore have first-block coordinates +/-1.
The lattice itself enforces only their odd parity when the embedding
coordinate is oriented to +1; returned vectors are explicitly filtered for
the required +/-1 shape before public-key validation.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import time

import numpy as np
from fpylll import BKZ, Enumeration, EvaluatorStrategy, GSO, IntegerMatrix, LLL
from fpylll.fplll.enumeration import EnumerationError

import darts_partial_lattice as core


# A labels-free, nested schedule.  Every support position, alternative label,
# equation, stopping decision, and final validation is computed from the score
# blob and public key.  The schedule was fixed after exploratory work on the
# demonstrated target, so it is reproducible but is not an out-of-sample
# success-probability experiment.
PUBLIC_SUPPORT_LADDER = (
    # u0, u1, anomalous 32-coefficient s0 blocks, public equations
    (32, 2, 1, 32),
    (64, 2, 2, 40),
    (64, 2, 3, 48),
    (96, 8, 4, 56),
    (128, 16, 6, 64),
    (160, 32, 8, 72),
)

PUBLIC_WIDTH_MULTIPLIERS = (1.0, 9.0 / 8.0, 5.0 / 4.0, 11.0 / 8.0, 3.0 / 2.0)
PUBLIC_WIDTH_PAIR_LADDER = tuple(sorted(
    ((left, right)
     for left in PUBLIC_WIDTH_MULTIPLIERS
     for right in PUBLIC_WIDTH_MULTIPLIERS),
    key=lambda pair: (max(pair), sum(pair), pair[0], pair[1]),
))


def stable_smallest(values: np.ndarray, count: int) -> np.ndarray:
    """Return public indices ordered by (value,index), independent of sort ties."""
    indices = np.arange(len(values), dtype=np.int64)
    return np.lexsort((indices, values))[:count]


def stable_largest_abs_deviation(values: np.ndarray, center: float,
                                 count: int) -> np.ndarray:
    """Return public indices ordered by (-abs(value-center),index)."""
    indices = np.arange(len(values), dtype=np.int64)
    return np.lexsort((indices, -np.abs(values - center)))[:count]


def likelihood_order(theta: np.ndarray, means: np.ndarray,
                     widths: np.ndarray) -> np.ndarray:
    priors = np.array([0.15, 0.70, 0.15])
    order = np.empty((2, core.N, 3), dtype=np.int64)
    for p in range(2):
        lp = (
            np.log(priors)[None, :]
            - np.log(widths[p])
            - 0.5 * ((theta[p, :, None] - means[p][None, :]) /
                     widths[p]) ** 2
        )
        order[p] = np.argsort(lp, axis=1, kind="stable") - 1
    return order


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("score", type=Path)
    ap.add_argument("matrix", type=Path)
    ap.add_argument("--labels", type=Path)
    ap.add_argument("--support0", type=Path)
    ap.add_argument("--support1", type=Path)
    ap.add_argument("--u0", type=int, default=96)
    ap.add_argument("--u1", type=int, default=15)
    ap.add_argument(
        "--ladder-rung", type=int,
        help=("use one fixed labels-free support rung numbered from zero; "
              "this overrides u0, u1, block0-size/count, and equations"),
    )
    ap.add_argument(
        "--public-sigma-multipliers", type=float, nargs=2,
        metavar=("LAMBDA0", "LAMBDA1"),
        help=("derive shared widths from the public scores, then multiply "
              "them by these two positive public ladder values"),
    )
    ap.add_argument(
        "--public-width-rung", type=int,
        help=("use one fixed public classifier-width pair numbered from zero; "
              "the 25 pairs use multipliers {1,9/8,5/4,11/8,3/2}"),
    )
    ap.add_argument(
        "--edge0-prefix", type=int, default=0,
        help="also select this many public coefficients from the start of s0",
    )
    ap.add_argument(
        "--edge0-suffix", type=int, default=0,
        help="also select this many public coefficients from the end of s0",
    )
    ap.add_argument(
        "--block0-size", type=int, default=0,
        help="partition s0 into public-score blocks of this size",
    )
    ap.add_argument(
        "--block0-count", type=int, default=0,
        help="also select this many s0 blocks with the most anomalous mean",
    )
    ap.add_argument(
        "--both-zero-directions", action="store_true",
        help="offer both legal nonzero labels whenever the public guess is zero",
    )
    ap.add_argument(
        "--both-zero-min-confidence", type=float,
        help=("offer both legal nonzero labels for zero guesses whose public "
              "log-likelihood gap is at least this value"),
    )
    ap.add_argument("--truth-directions", action="store_true")
    ap.add_argument(
        "--opposite", type=Path,
        help="optional public list of flat p*512+i positions using third label",
    )
    ap.add_argument("--equations", type=int, default=64)
    ap.add_argument("--embedding", type=int, default=1)
    ap.add_argument("--lll-delta", type=float, default=0.99)
    ap.add_argument(
        "--lll-method", choices=("wrapper", "proved", "heuristic", "fast"),
        default="proved",
    )
    ap.add_argument(
        "--float-type",
        choices=("double", "long double", "dpe", "dd", "qd", "mpfr"),
        default="mpfr",
    )
    ap.add_argument("--precision", type=int, default=256)
    ap.add_argument("--bkz", type=int, default=0)
    ap.add_argument("--bkz-loops", type=int, default=1)
    ap.add_argument("--basis-input", type=Path)
    ap.add_argument("--basis-output", type=Path)
    ap.add_argument("--skip-lll", action="store_true")
    ap.add_argument("--enumerate-bound", type=float, default=0.0)
    ap.add_argument("--enumerate-first", action="store_true")
    ap.add_argument("--output-secret", type=Path)
    args = ap.parse_args()

    if args.ladder_rung is not None:
        if not 0 <= args.ladder_rung < len(PUBLIC_SUPPORT_LADDER):
            raise ValueError(
                f"--ladder-rung must lie in 0..{len(PUBLIC_SUPPORT_LADDER)-1}"
            )
        args.u0, args.u1, args.block0_count, args.equations = (
            PUBLIC_SUPPORT_LADDER[args.ladder_rung]
        )
        args.block0_size = 32
        args.edge0_prefix = 0
        args.edge0_suffix = 0
        print(
            f"public_ladder_rung={args.ladder_rung} u0={args.u0} "
            f"u1={args.u1} block0_size=32 "
            f"block0_count={args.block0_count} equations={args.equations}",
            flush=True,
        )

    signatures, theta = core.load_score(args.score)
    public_matrix = core.load_matrix(args.matrix)
    widths = core.DEFAULT_SIGMAS.copy()
    if (args.public_width_rung is not None and
            args.public_sigma_multipliers is not None):
        raise ValueError(
            "choose either --public-width-rung or "
            "--public-sigma-multipliers"
        )
    if args.public_width_rung is not None:
        if not 0 <= args.public_width_rung < len(PUBLIC_WIDTH_PAIR_LADDER):
            raise ValueError(
                f"--public-width-rung must lie in "
                f"0..{len(PUBLIC_WIDTH_PAIR_LADDER)-1}"
            )
        args.public_sigma_multipliers = list(
            PUBLIC_WIDTH_PAIR_LADDER[args.public_width_rung]
        )
        print(
            f"public_width_rung={args.public_width_rung}",
            flush=True,
        )
    if args.public_sigma_multipliers is not None:
        multipliers = np.asarray(args.public_sigma_multipliers, dtype=float)
        if np.any(multipliers <= 0):
            raise ValueError("public sigma multipliers must be positive")
        base_widths = core.fit_public_scales(theta)
        widths = base_widths * multipliers
        print(
            f"public_base_widths={base_widths.tolist()} "
            f"public_width_multipliers={multipliers.tolist()} "
            f"classifier_widths={widths.tolist()}",
            flush=True,
        )
    guess, confidence, means = core.classify(theta, widths)
    orders = likelihood_order(theta, means, widths)

    truth = None
    if args.labels is not None:
        flat = np.loadtxt(args.labels, dtype=np.int64)
        if flat.shape != (3 * core.N,):
            raise ValueError("invalid labels")
        truth = flat.reshape(3, core.N)

    if args.support0 is None:
        extra_blocks = np.empty(0, dtype=np.int64)
        selected_blocks = np.empty(0, dtype=np.int64)
        if args.block0_size or args.block0_count:
            if (args.block0_size <= 0 or core.N % args.block0_size or
                    args.block0_count <= 0 or
                    args.block0_count > core.N // args.block0_size):
                raise ValueError("invalid public anomaly-block rule")
            block_means = np.array([
                theta[0, start:start + args.block0_size].mean()
                for start in range(0, core.N, args.block0_size)
            ])
            center = float(np.median(block_means))
            selected_blocks = stable_largest_abs_deviation(
                block_means, center, args.block0_count
            )
            extra_blocks = np.concatenate([
                np.arange(int(block) * args.block0_size,
                          (int(block) + 1) * args.block0_size,
                          dtype=np.int64)
                for block in selected_blocks
            ])
            print(
                f"public_anomaly_blocks={selected_blocks.tolist()} "
                f"block_size={args.block0_size} center={center:.9f}",
                flush=True,
            )
        chosen0 = np.unique(np.concatenate((
            stable_smallest(confidence[0], args.u0),
            np.arange(args.edge0_prefix, dtype=np.int64),
            np.arange(core.N - args.edge0_suffix, core.N, dtype=np.int64),
            extra_blocks,
        )))
    else:
        chosen0 = np.atleast_1d(np.loadtxt(args.support0, dtype=np.int64))
    if args.support1 is None:
        chosen1 = stable_smallest(confidence[1], args.u1)
    else:
        chosen1 = np.atleast_1d(np.loadtxt(args.support1, dtype=np.int64))
    chosen = [
        chosen0[stable_smallest(confidence[0, chosen0], len(chosen0))],
        chosen1[stable_smallest(confidence[1, chosen1], len(chosen1))],
    ]
    for p in range(2):
        if (chosen[p].ndim != 1 or len(np.unique(chosen[p])) != len(chosen[p]) or
                np.any(chosen[p] < 0) or np.any(chosen[p] >= core.N)):
            raise ValueError(f"invalid support for polynomial {p}")

    opposite: set[int] = set()
    if args.opposite is not None:
        opposite = set(
            int(v) for v in np.atleast_1d(
                np.loadtxt(args.opposite, dtype=np.int64)
            )
        )
    choices: list[tuple[int, int, int]] = []
    if args.truth_directions:
        if truth is None:
            raise ValueError("--truth-directions requires --labels")
    for p in range(2):
        for raw_i in chosen[p]:
            i = int(raw_i)
            if args.truth_directions:
                delta = int(truth[p, i] - guess[p, i])
                direction = delta if delta else int(orders[p, i, -2] - guess[p, i])
                if abs(direction) != 1:
                    raise ValueError("non-adjacent diagnostic correction")
                choices.append((p, i, direction))
                continue
            both_zero = (
                args.both_zero_directions or
                (args.both_zero_min_confidence is not None and
                 confidence[p, i] >= args.both_zero_min_confidence)
            )
            if both_zero and guess[p, i] == 0:
                choices.extend(((p, i, -1), (p, i, 1)))
                continue
            alternative = int(orders[p, i, -2])
            if p * core.N + i in opposite:
                alternative = int(orders[p, i, 0])
            choices.append((p, i, alternative - int(guess[p, i])))
    u = len(choices)
    directions = np.array([direction for _, _, direction in choices], dtype=np.int64)
    if not np.isin(directions, (-1, 1)).all():
        raise ValueError("binary directions must be +/-1")

    m = args.equations
    if not 1 <= m <= core.N:
        raise ValueError("--equations must lie in 1..512")
    conv = [core.negacyclic_matrix(public_matrix[p]) for p in range(2)]
    columns = np.column_stack(
        [conv[p][:m, i] * directions[j]
         for j, (p, i, _) in enumerate(choices)]
    ) % core.Q
    target = np.zeros(core.N, dtype=np.int64)
    target[0] = core.HALF_Q
    rhs = (target - core.product(public_matrix, guess))[:m] % core.Q

    print(
        f"signatures={signatures} unknowns={u} support_sizes="
        f"{len(chosen[0])},{len(chosen[1])} equations={m}", flush=True,
    )
    if truth is not None:
        selected = {(p, int(i)) for p in range(2) for i in chosen[p]}
        errors = [(p, i) for p, i in selected if guess[p, i] != truth[p, i]]
        total = int(np.count_nonzero(guess != truth[:2]))
        representable = sum(any(
            cp == p and ci == i and
            truth[p, i] - guess[p, i] == direction
            for cp, ci, direction in choices
        ) for p, i in errors)
        xtrue = np.array(
            [int(truth[p, i] - guess[p, i] == direction)
             for p, i, direction in choices],
            dtype=np.int64,
        )
        relation = (rhs - columns @ xtrue) % core.Q
        relation = np.where(relation > core.Q // 2,
                            relation - core.Q, relation)
        print(
            f"diagnostic_errors_covered={len(errors)}/{total} "
            f"representable={representable}/{len(errors)} "
            f"target_norm2={u + 4 * np.count_nonzero(relation) + args.embedding**2} "
            f"relation={'OK' if np.array_equal(relation, truth[2, :m]) else 'FAILED'}",
            flush=True,
        )

    dim = u + m + 1
    basis = IntegerMatrix(dim, dim)
    modulus = 2 * core.Q
    for i in range(m):
        basis[i, u + i] = modulus
    for j in range(u):
        basis[m + j, j] = 2
        for i in range(m):
            basis[m + j, u + i] = 2 * int(columns[i, j])
    for j in range(u):
        basis[dim - 1, j] = 1
    for i in range(m):
        basis[dim - 1, u + i] = 2 * int(rhs[i])
    basis[dim - 1, dim - 1] = args.embedding

    if args.basis_input is not None:
        basis = IntegerMatrix.from_file(str(args.basis_input))
        if basis.nrows != dim or basis.ncols != dim:
            raise ValueError("basis input dimension mismatch")

    options = {"float_type": args.float_type}
    if args.precision:
        options["precision"] = args.precision
    started = time.monotonic()
    print(f"reduction_start dimension={dim}", flush=True)
    if not args.skip_lll:
        LLL.reduction(
            basis, delta=args.lll_delta, eta=0.501,
            method=args.lll_method, **options,
        )
        print(f"lll_done wall={time.monotonic()-started:.3f}", flush=True)
    if args.bkz:
        BKZ.reduction(
            basis,
            BKZ.Param(block_size=args.bkz, max_loops=args.bkz_loops),
            **options,
        )
        print(f"bkz_done wall={time.monotonic()-started:.3f}", flush=True)
    if args.basis_output is not None:
        args.basis_output.write_text(str(basis) + "\n")
        print(f"basis_output={args.basis_output}", flush=True)

    def try_vector(vector: list[int] | tuple[int, ...], source: str) -> bool:
        last = int(vector[-1])
        if abs(last) != args.embedding:
            return False
        sign = 1 if last == args.embedding else -1
        y = sign * np.array(vector[:u], dtype=np.int64)
        if not np.isin(y, (-1, 1)).all():
            return False
        x = (1 - y) // 2
        candidate = guess.copy()
        for bit, (p, i, direction) in zip(x, choices):
            candidate[p, i] += int(bit * direction)
        valid, recovered_e = core.assess_candidate(candidate, public_matrix, truth)
        print(
            f"binary_candidate={source} selected_bits={np.count_nonzero(x)} "
            f"changed_coefficients={np.count_nonzero(candidate != guess)} "
            f"valid={valid}", flush=True,
        )
        if valid:
            if args.output_secret is not None:
                complete = np.concatenate((candidate.ravel(), recovered_e))
                args.output_secret.write_text(
                    "".join(f"{int(v)}\n" for v in complete)
                )
            print("completion=RECOVERED", flush=True)
        return valid

    for row in range(dim):
        if try_vector([int(basis[row, j]) for j in range(dim)], f"row:{row}"):
            return

    if args.enumerate_bound:
        gso = GSO.Mat(basis, float_type=args.float_type, update=True)
        enum = Enumeration(
            gso, nr_solutions=1,
            strategy=(EvaluatorStrategy.FIRST_N_SOLUTIONS
                      if args.enumerate_first
                      else EvaluatorStrategy.BEST_N_SOLUTIONS),
        )
        print(f"enumeration_start bound={args.enumerate_bound}", flush=True)
        try:
            solutions = enum.enumerate(0, dim, args.enumerate_bound, 0)
        except EnumerationError:
            solutions = []
        print(f"enumeration_done solutions={len(solutions)}", flush=True)
        for distance, coefficients in solutions:
            vector = basis.multiply_left([int(round(v)) for v in coefficients])
            if try_vector(vector, f"enumeration:{distance:.6f}"):
                return
    print("completion=FAILED", flush=True)


if __name__ == "__main__":
    main()

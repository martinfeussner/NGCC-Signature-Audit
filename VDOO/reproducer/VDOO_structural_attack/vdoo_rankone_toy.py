#!/usr/bin/env python3
"""Toy validation of the rank-one derivative attack on submitted VDOO keys.

The submitted reference implementation keeps only the matching vinegar-oil
column in every oil equation.  Consequently, for every second-layer oil basis
vector z_j the derivative x -> D F(z_j, x) has rank one.  This script hides a
toy central map with random input/output transformations and recovers those
projective lines using three random derivative evaluations and only small
linear algebra over GF(16).

This is a structural experiment.  It does not use the secret transformations
during recovery; they are retained solely to check the recovered subspace.
"""

from __future__ import annotations

import itertools
import numpy as np


def gf4_mul_2(a: int) -> int:
    return ((a << 1) ^ ((a >> 1) * 7)) & 3


def gf4_mul(a: int, b: int) -> int:
    return (a * (b & 1)) ^ (gf4_mul_2(a) * (b >> 1))


def gf16_mul_scalar(a: int, b: int) -> int:
    a0, a1 = a & 3, a >> 2
    b0, b1 = b & 3, b >> 2
    a0b0 = gf4_mul(a0, b0)
    a1b1 = gf4_mul(a1, b1)
    cross = gf4_mul(a0 ^ a1, b0 ^ b1) ^ a0b0 ^ a1b1
    return ((cross ^ a1b1) << 2) ^ a0b0 ^ gf4_mul_2(a1b1)


MUL = np.fromfunction(
    np.vectorize(lambda a, b: gf16_mul_scalar(int(a), int(b))),
    (16, 16),
    dtype=int,
).astype(np.uint8)
INV = np.zeros(16, dtype=np.uint8)
for _a in range(1, 16):
    INV[_a] = int(np.flatnonzero(MUL[_a] == 1)[0])


def gf_rank_rref(a: np.ndarray) -> tuple[int, np.ndarray, list[int]]:
    """Return rank, RREF, and pivot columns over GF(16)."""
    m = np.asarray(a, dtype=np.uint8).copy()
    nr, nc = m.shape
    pivots: list[int] = []
    row = 0
    for col in range(nc):
        nz = np.flatnonzero(m[row:, col])
        if not len(nz):
            continue
        p = row + int(nz[0])
        if p != row:
            m[[row, p]] = m[[p, row]]
        m[row] = MUL[INV[m[row, col]], m[row]]
        factors = m[:, col].copy()
        factors[row] = 0
        active = np.flatnonzero(factors)
        if len(active):
            m[active] ^= MUL[factors[active, None], m[row][None, :]]
        pivots.append(col)
        row += 1
        if row == nr:
            break
    return row, m, pivots


def gf_nullspace(a: np.ndarray) -> np.ndarray:
    rank, rref, pivots = gf_rank_rref(a)
    free = [j for j in range(a.shape[1]) if j not in set(pivots)]
    out = np.zeros((len(free), a.shape[1]), dtype=np.uint8)
    for k, f in enumerate(free):
        out[k, f] = 1
        for i, p in enumerate(pivots):
            out[k, p] = rref[i, f]
    assert rank + len(free) == a.shape[1]
    return out


def gf_matmul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    assert a.shape[1] == b.shape[0]
    out = np.zeros((a.shape[0], b.shape[1]), dtype=np.uint8)
    for k in range(a.shape[1]):
        out ^= MUL[a[:, k, None], b[k, None, :]]
    return out


def gf_matvec(a: np.ndarray, x: np.ndarray) -> np.ndarray:
    out = np.zeros(a.shape[0], dtype=np.uint8)
    for k in range(a.shape[1]):
        out ^= MUL[a[:, k], x[k]]
    return out


def gf_inverse(a: np.ndarray) -> np.ndarray:
    n = a.shape[0]
    aug = np.concatenate((a.copy(), np.eye(n, dtype=np.uint8)), axis=1)
    rank, rref, pivots = gf_rank_rref(aug[:, :n])
    if rank != n or pivots != list(range(n)):
        raise ValueError("singular")
    # Repeat elimination on the actual augmented matrix.
    m = aug
    row = 0
    for col in range(n):
        p = row + int(np.flatnonzero(m[row:, col])[0])
        if p != row:
            m[[row, p]] = m[[p, row]]
        m[row] = MUL[INV[m[row, col]], m[row]]
        factors = m[:, col].copy()
        factors[row] = 0
        active = np.flatnonzero(factors)
        if len(active):
            m[active] ^= MUL[factors[active, None], m[row][None, :]]
        row += 1
    return m[:, n:]


def random_invertible(rng: np.random.Generator, n: int) -> np.ndarray:
    while True:
        a = rng.integers(0, 16, size=(n, n), dtype=np.uint8)
        if gf_rank_rref(a)[0] == n:
            return a


def add_random_alternating_prefix(
    rng: np.random.Generator, b: np.ndarray, poly: int, prefix: int
) -> None:
    for i in range(prefix):
        for j in range(i + 1, prefix):
            c = int(rng.integers(0, 16))
            b[poly, i, j] = c
            b[poly, j, i] = c


def make_hidden_toy(
    rng: np.random.Generator, v: int, d: int, o1: int, o2: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return public polar matrices and the two secret transformations."""
    m = d + o1 + o2
    n = v + m
    central = np.zeros((m, n, n), dtype=np.uint8)

    for r in range(d):
        own = v + r
        add_random_alternating_prefix(rng, central, r, own)
        for i in range(own):
            c = int(rng.integers(0, 16))
            central[r, i, own] = central[r, own, i] = c

    prefix = v + d
    for j in range(o1):
        r, own = d + j, prefix + j
        add_random_alternating_prefix(rng, central, r, prefix)
        for i in range(prefix):
            c = int(rng.integers(0, 16))
            central[r, i, own] = central[r, own, i] = c

    prefix = v + d + o1
    for j in range(o2):
        r, own = d + o1 + j, prefix + j
        add_random_alternating_prefix(rng, central, r, prefix)
        for i in range(prefix):
            c = int(rng.integers(0, 16))
            central[r, i, own] = central[r, own, i] = c

    t = random_invertible(rng, n)
    s = random_invertible(rng, m)
    public = np.zeros_like(central)
    for a in range(m):
        mixed = np.zeros((n, n), dtype=np.uint8)
        for r in range(m):
            if s[a, r]:
                mixed ^= MUL[s[a, r], central[r]]
        public[a] = gf_matmul(t.T, gf_matmul(mixed, t))
    return public, s, t


def derivative_matrix(polars: np.ndarray, x: np.ndarray) -> np.ndarray:
    """Rows are the linear forms D P_a(x, .)."""
    return np.stack([gf_matvec(b, x) for b in polars])


def projective_points_2() -> list[np.ndarray]:
    points = []
    for a, b in itertools.product(range(16), repeat=2):
        points.append(np.array((1, a, b), dtype=np.uint8))
    for b in range(16):
        points.append(np.array((0, 1, b), dtype=np.uint8))
    points.append(np.array((0, 0, 1), dtype=np.uint8))
    return points


def projective_points(dimension: int):
    """Yield normalized points of P^(dimension-1)(GF(16))."""
    for pivot in range(dimension):
        tail = dimension - pivot - 1
        for values in itertools.product(range(16), repeat=tail):
            point = np.zeros(dimension, dtype=np.uint8)
            point[pivot] = 1
            if tail:
                point[pivot + 1 :] = values
            yield point


def normalize_line(x: np.ndarray) -> tuple[int, ...]:
    nz = np.flatnonzero(x)
    if not len(nz):
        raise ValueError("zero vector")
    return tuple(int(v) for v in MUL[INV[x[nz[0]]], x])


def projective_vectors_of_small_space(basis: np.ndarray):
    k = len(basis)
    if k == 0:
        return
    if k > 3:
        # This should not occur with the toy dimensions and generic samples.
        return
    for pivot in range(k):
        tail = k - pivot - 1
        for values in itertools.product(range(16), repeat=tail):
            coeff = np.zeros(k, dtype=np.uint8)
            coeff[pivot] = 1
            if tail:
                coeff[pivot + 1 :] = values
            x = np.zeros(basis.shape[1], dtype=np.uint8)
            for i, c in enumerate(coeff):
                if c:
                    x ^= MUL[c, basis[i]]
            yield x


def recover_rank_one_lines(
    polars: np.ndarray, rng: np.random.Generator, trials: int = 4
) -> list[np.ndarray]:
    m, n, _ = polars.shape
    found: dict[tuple[int, ...], np.ndarray] = {}
    for _ in range(trials):
        z = rng.integers(0, 16, size=(3, n), dtype=np.uint8)
        evals = []
        for zi in z:
            # L_zi maps x to D P(x, zi); symmetry gives B_a zi.
            evals.append(np.stack([gf_matvec(b, zi) for b in polars]))

        for c in projective_points_2():
            pivot = int(np.flatnonzero(c)[0])
            blocks = []
            for j in range(3):
                if j == pivot:
                    continue
                # c[j] * image_pivot + c[pivot] * image_j = 0.
                blocks.append(MUL[c[j], evals[pivot]] ^ MUL[c[pivot], evals[j]])
            ker = gf_nullspace(np.concatenate(blocks, axis=0))
            for x in projective_vectors_of_small_space(ker) or ():
                if gf_rank_rref(derivative_matrix(polars, x))[0] == 1:
                    found[normalize_line(x)] = x.copy()
    return list(found.values())


def recover_rank_one_lines_projective(
    polars: np.ndarray,
    rng: np.random.Generator,
    evaluations: int,
    expected: int | None = None,
    progress_every: int = 0,
) -> list[np.ndarray]:
    """Recover rank-one Jacobian points using a projective multipencil.

    With t evaluation vectors, a projective label c in P^(t-1) defines t-1
    proportionality relations.  Whenever (t-1)*m >= n, the stacked system is
    generically injective and has a kernel exactly at a rank-one point.
    """
    m, n, _ = polars.shape
    if (evaluations - 1) * m < n:
        raise ValueError("too few evaluations for an injective stacked system")
    z = rng.integers(0, 16, size=(evaluations, n), dtype=np.uint8)
    evals = [np.stack([gf_matvec(b, zi) for b in polars]) for zi in z]
    found: dict[tuple[int, ...], np.ndarray] = {}

    for count, c in enumerate(projective_points(evaluations), start=1):
        pivot = int(np.flatnonzero(c)[0])
        blocks = []
        for j in range(evaluations):
            if j == pivot:
                continue
            blocks.append(MUL[c[j], evals[pivot]] ^ MUL[c[pivot], evals[j]])
        stacked = np.concatenate(blocks, axis=0)
        rank, rref, pivots = gf_rank_rref(stacked)
        if rank < n:
            free = [j for j in range(n) if j not in set(pivots)]
            ker = np.zeros((len(free), n), dtype=np.uint8)
            for k, f in enumerate(free):
                ker[k, f] = 1
                for i, p in enumerate(pivots):
                    ker[k, p] = rref[i, f]
            for x in projective_vectors_of_small_space(ker) or ():
                if gf_rank_rref(derivative_matrix(polars, x))[0] == 1:
                    found[normalize_line(x)] = x.copy()
        if progress_every and count % progress_every == 0:
            suffix = f"/{expected}" if expected else ""
            print(
                f"  multipencil labels tested: {count}{suffix}; "
                f"rank-one lines={len(found)}",
                flush=True,
            )
    return list(found.values())


def recover_rank_one_lines_split5(
    polars: np.ndarray,
    rng: np.random.Generator,
    progress_every: int = 0,
) -> list[np.ndarray]:
    """Five-evaluation search with a 3+2 meet-in-the-middle split.

    For each label in P^2(GF(16)), the first two proportionality equations
    leave a kernel K of dimension n-2m.  The last two label coordinates are
    then enumerated on two  m x dim(K) restrictions.  For VDOO's 30x97
    quotient this replaces 69,905 eliminations of 120x97 matrices by the same
    number of eliminations of only 60x37 matrices.
    """
    m, n, _ = polars.shape
    if 4 * m < n or 2 * m >= n:
        raise ValueError("split5 expects 2m < n <= 4m")
    z = rng.integers(0, 16, size=(5, n), dtype=np.uint8)
    evals = [np.stack([gf_matvec(b, zi) for b in polars]) for zi in z]
    found: dict[tuple[int, ...], np.ndarray] = {}
    labels = 0

    for c in projective_points(3):
        pivot = int(np.flatnonzero(c)[0])
        first_blocks = []
        for j in range(3):
            if j == pivot:
                continue
            first_blocks.append(MUL[c[j], evals[pivot]] ^ evals[j])
        k_basis = gf_nullspace(np.concatenate(first_blocks, axis=0))
        if not len(k_basis):
            continue
        kt = k_basis.T
        ep = gf_matmul(evals[pivot], kt)
        e3 = gf_matmul(evals[3], kt)
        e4 = gf_matmul(evals[4], kt)

        for a, b in itertools.product(range(16), repeat=2):
            labels += 1
            reduced = np.concatenate((MUL[a, ep] ^ e3, MUL[b, ep] ^ e4), axis=0)
            ker_coeff = gf_nullspace(reduced)
            for u in projective_vectors_of_small_space(ker_coeff) or ():
                x = np.zeros(n, dtype=np.uint8)
                for ui, row in zip(u, k_basis):
                    if ui:
                        x ^= MUL[ui, row]
                if gf_rank_rref(derivative_matrix(polars, x))[0] == 1:
                    found[normalize_line(x)] = x.copy()
            if progress_every and labels % progress_every == 0:
                print(
                    f"  split multipencil labels tested: {labels}/69888; "
                    f"rank-one lines={len(found)}",
                    flush=True,
                )
    return list(found.values())


def same_rowspace(a: np.ndarray, b: np.ndarray) -> bool:
    ra = gf_rank_rref(a)[0]
    rb = gf_rank_rref(b)[0]
    rab = gf_rank_rref(np.concatenate((a, b), axis=0))[0]
    return ra == rb == rab


def main() -> None:
    rng = np.random.default_rng(0x56444F4F)
    v, d, o1, o2 = 3, 2, 2, 3
    polars, _s, t = make_hidden_toy(rng, v, d, o1, o2)
    recovered = recover_rank_one_lines(polars, rng)

    tinv = gf_inverse(t)
    oil2_start = v + d + o1
    expected = tinv[:, oil2_start : oil2_start + o2].T.copy()
    got = np.stack(recovered) if recovered else np.zeros((0, polars.shape[1]), dtype=np.uint8)

    print(f"toy dimensions: m={polars.shape[0]}, n={polars.shape[1]}, q=16")
    print(f"rank-one lines recovered: {len(recovered)} (expected {o2})")
    print(f"recovered span dimension: {gf_rank_rref(got)[0]}")
    print(f"secret O2 span dimension: {gf_rank_rref(expected)[0]}")
    print(f"exact O2 recovery: {same_rowspace(got, expected)}")
    if len(recovered) != o2 or not same_rowspace(got, expected):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

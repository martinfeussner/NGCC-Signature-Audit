#!/usr/bin/env python3
"""Linear algebra used by the public-key-only VDOO structural attack."""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import numpy as np

from vdoo_rankone_toy import (
    INV,
    MUL,
    gf_matmul,
    gf_nullspace,
    gf_rank_rref,
    normalize_line,
)


SQ = MUL[np.arange(16, dtype=np.uint8), np.arange(16, dtype=np.uint8)]


def gf_row_comb(coeff: np.ndarray, rows: np.ndarray) -> np.ndarray:
    out = np.zeros(rows.shape[1], dtype=np.uint8)
    for c, row in zip(coeff, rows):
        if c:
            out ^= MUL[c, row]
    return out


def gf_matvec(a: np.ndarray, x: np.ndarray) -> np.ndarray:
    out = np.zeros(a.shape[0], dtype=np.uint8)
    for k in range(a.shape[1]):
        if x[k]:
            out ^= MUL[a[:, k], x[k]]
    return out


def rowspace_contains(rows: np.ndarray, x: np.ndarray) -> bool:
    if not len(rows):
        return not np.any(x)
    return gf_rank_rref(np.concatenate((rows, x[None, :]), axis=0))[0] == gf_rank_rref(rows)[0]


def independent_append(rows: np.ndarray, x: np.ndarray) -> np.ndarray | None:
    trial = np.concatenate((rows, x[None, :]), axis=0) if len(rows) else x[None, :]
    if gf_rank_rref(trial)[0] == len(rows) + 1:
        return trial
    return None


def complement_standard_columns(rows: np.ndarray, ambient: int) -> list[int]:
    rank, _rref, pivots = gf_rank_rref(rows)
    if rank != len(rows):
        raise ValueError("subspace basis is dependent")
    return [j for j in range(ambient) if j not in set(pivots)]


def normalize_subspace(rows: np.ndarray) -> np.ndarray:
    rank, rref, _pivots = gf_rank_rref(rows)
    return rref[:rank].copy()


@dataclass
class QuadraticMap:
    """Homogeneous quadratic map over GF(16).

    `polars[a]` is the alternating polar matrix of output a.  `diags[a]`
    contains the coefficients of x_i^2.  Together they uniquely encode the
    quadratic form in characteristic two.
    """

    polars: np.ndarray  # (m,n,n)
    diags: np.ndarray   # (m,n)

    @property
    def m(self) -> int:
        return self.polars.shape[0]

    @property
    def n(self) -> int:
        return self.polars.shape[1]

    def combine(self, coeff: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        b = np.zeros((self.n, self.n), dtype=np.uint8)
        d = np.zeros(self.n, dtype=np.uint8)
        for c, bi, di in zip(coeff, self.polars, self.diags):
            if c:
                b ^= MUL[c, bi]
                d ^= MUL[c, di]
        return b, d

    @staticmethod
    def eval_form(b: np.ndarray, d: np.ndarray, x: np.ndarray) -> int:
        ii, jj = np.triu_indices(len(x))
        coeff = b[ii, jj].copy()
        diagonal = ii == jj
        coeff[diagonal] = d[ii[diagonal]]
        monomials = MUL[x[ii], x[jj]]
        return int(np.bitwise_xor.reduce(MUL[coeff, monomials], initial=np.uint8(0)))

    def evaluate(self, x: np.ndarray) -> np.ndarray:
        ii, jj = np.triu_indices(self.n)
        coeff = self.polars[:, ii, jj].copy()
        diagonal = ii == jj
        coeff[:, diagonal] = self.diags[:, ii[diagonal]]
        monomials = MUL[x[ii], x[jj]]
        return np.bitwise_xor.reduce(MUL[coeff, monomials[None, :]], axis=1)

    def essential_rank(self, coeff: np.ndarray) -> int:
        """Minimum number of variables needed by a characteristic-two form."""
        b, d = self.combine(coeff)
        rank, _rref, _pivots = gf_rank_rref(b)
        radical = gf_nullspace(b)
        for z in radical:
            if self.eval_form(b, d, z):
                return rank + 1
        return rank

    def output_transform(self, rows: np.ndarray) -> "QuadraticMap":
        bp = np.zeros((len(rows), self.n, self.n), dtype=np.uint8)
        dp = np.zeros((len(rows), self.n), dtype=np.uint8)
        for i, row in enumerate(rows):
            bp[i], dp[i] = self.combine(row)
        return QuadraticMap(bp, dp)

    def input_restrict(self, columns: np.ndarray) -> "QuadraticMap":
        """Substitute x = columns*z, where columns has shape old_n x new_n."""
        new_n = columns.shape[1]
        bp = np.zeros((self.m, new_n, new_n), dtype=np.uint8)
        dp = np.zeros((self.m, new_n), dtype=np.uint8)
        for a, (b, d) in enumerate(zip(self.polars, self.diags)):
            bp[a] = gf_matmul(columns.T, gf_matmul(b, columns))
            for j in range(new_n):
                dp[a, j] = self.eval_form(b, d, columns[:, j])
        return QuadraticMap(bp, dp)

    def quotient(self, input_kernel: np.ndarray, output_kernel: np.ndarray) -> tuple["QuadraticMap", np.ndarray, np.ndarray]:
        """Quotient by input/output subspaces known to be compatible.

        Returns the quotient map, the chosen input representative matrix R
        (`x=R*z`), and the output projection matrix pi (`ybar=pi*y`).
        """
        input_kernel = normalize_subspace(input_kernel)
        output_kernel = normalize_subspace(output_kernel)
        free = complement_standard_columns(input_kernel, self.n)
        r = np.eye(self.n, dtype=np.uint8)[:, free]
        pi = gf_nullspace(output_kernel)
        transformed = self.output_transform(pi).input_restrict(r)
        return transformed, r, pi


def recover_output_hyperplane(
    qmap: QuadraticMap,
    containing: np.ndarray,
    threshold: int,
    rng: np.random.Generator,
    checks: int = 2,
    max_rank_tests: int = 20000,
) -> tuple[np.ndarray, int]:
    """Recover a codimension-one space whose forms use <= threshold variables.

    Random singular forms outside the hidden hyperplane cause false positives.
    We reject them by requiring several random translates by already-confirmed
    hyperplane vectors to retain the rank bound.
    """
    containing = normalize_subspace(containing)
    dim = len(containing)
    if dim < 2:
        raise ValueError("cannot descend a one-dimensional space")
    cache: dict[tuple[int, ...], bool] = {}
    tests = 0

    def member(x: np.ndarray) -> bool:
        nonlocal tests
        key = normalize_line(x)
        if key not in cache:
            cache[key] = qmap.essential_rank(np.array(key, dtype=np.uint8)) <= threshold
            tests += 1
            if tests > max_rank_tests:
                raise RuntimeError("rank-test budget exhausted")
        return cache[key]

    # The last descent is a projective line.  Any maximal-rank point satisfying
    # the bound gives a valid equivalent first layer.
    if dim == 2:
        candidates = []
        for lam in range(16):
            x = containing[0] ^ MUL[lam, containing[1]]
            if member(x):
                candidates.append((qmap.essential_rank(x), x))
        if member(containing[1]):
            candidates.append((qmap.essential_rank(containing[1]), containing[1]))
        exact = [x for r, x in candidates if r == threshold]
        if not exact:
            raise RuntimeError("no full-rank first-layer form found")
        return normalize_subspace(exact[0][None, :]), tests

    accepted: list[np.ndarray] = []
    seen: set[tuple[int, ...]] = set()
    h = np.zeros((0, qmap.m), dtype=np.uint8)

    def random_in(space: np.ndarray) -> np.ndarray:
        while True:
            coeff = rng.integers(0, 16, size=len(space), dtype=np.uint8)
            if np.any(coeff):
                return gf_row_comb(coeff, space)

    def compatible_with_h(x: np.ndarray, space: np.ndarray) -> bool:
        for _ in range(checks):
            z = random_in(space)
            for lam in range(1, 16):
                if not member(x ^ MUL[lam, z]):
                    return False
        return True

    while len(h) < dim - 1:
        x = random_in(containing)
        key = normalize_line(x)
        if key in seen:
            continue
        seen.add(key)
        x = np.array(key, dtype=np.uint8)
        if not member(x):
            continue

        if len(h) == 0:
            # Find two independent accepted points whose complete sampled line
            # remains in the determinantal variety.
            for y in accepted:
                pair = np.stack((y, x))
                if gf_rank_rref(pair)[0] != 2:
                    continue
                ok = True
                for lam in range(1, 16):
                    if not member(x ^ MUL[lam, y]):
                        ok = False
                        break
                if ok:
                    h = normalize_subspace(pair)
                    break
            accepted.append(x)
            continue

        trial = independent_append(h, x)
        if trial is None:
            continue
        if compatible_with_h(x, h):
            h = normalize_subspace(trial)

    # Strong final check: random points of the recovered space must all obey
    # the bound.  A false point surviving the translate tests is overwhelmingly
    # unlikely to pass this check.
    for _ in range(32):
        if not member(random_in(h)):
            raise RuntimeError("candidate hyperplane failed closure check")
    return h, tests


def recover_output_flag(
    qmap: QuadraticMap,
    vinegar_dim: int,
    rng: np.random.Generator,
    verbose: bool = False,
) -> tuple[list[np.ndarray], int]:
    """Recover J_l = span of the first l hidden output equations."""
    flags: list[np.ndarray | None] = [None] * (qmap.m + 1)
    flags[qmap.m] = np.eye(qmap.m, dtype=np.uint8)
    total_tests = 0
    for l in range(qmap.m - 1, 0, -1):
        assert flags[l + 1] is not None
        last_error = None
        for _attempt in range(4):
            try:
                flags[l], used = recover_output_hyperplane(
                    qmap, flags[l + 1], vinegar_dim + l, rng
                )
                total_tests += used
                if verbose:
                    print(
                        f"  recovered J_{l}: dim={len(flags[l])}, "
                        f"threshold={vinegar_dim + l}, rank tests={used}",
                        flush=True,
                    )
                break
            except RuntimeError as exc:
                last_error = exc
        else:
            raise RuntimeError(f"failed to recover J_{l}: {last_error}")
    return [np.zeros((0, qmap.m), dtype=np.uint8)] + [x for x in flags[1:] if x is not None], total_tests


def ordered_forms_from_flag(flags: list[np.ndarray]) -> np.ndarray:
    rows: list[np.ndarray] = []
    current = np.zeros((0, flags[-1].shape[1]), dtype=np.uint8)
    for l in range(1, len(flags)):
        for x in flags[l]:
            trial = independent_append(current, x)
            if trial is not None:
                rows.append(x.copy())
                current = normalize_subspace(trial)
                break
        else:
            raise RuntimeError(f"flag step {l} did not grow")
    result = np.stack(rows)
    if gf_rank_rref(result)[0] != len(rows):
        raise RuntimeError("ordered output transform is singular")
    return result


def common_polar_kernel(polars: np.ndarray) -> np.ndarray:
    return gf_nullspace(np.concatenate(list(polars), axis=0))


def recover_tail_flag(ordered: QuadraticMap) -> list[np.ndarray]:
    """Recover K_l, the common polar kernel of the first l layer forms."""
    tails = [np.zeros((0, ordered.n), dtype=np.uint8)] * (ordered.m + 1)
    tails[0] = np.eye(ordered.n, dtype=np.uint8)  # not the secret K_0; unused
    for l in range(1, ordered.m + 1):
        tails[l] = normalize_subspace(common_polar_kernel(ordered.polars[:l]))
    return tails


def layer_directions(tails: list[np.ndarray], expected_vinegar: int) -> list[np.ndarray | None]:
    m = len(tails) - 1
    if len(tails[1]) != m - 1:
        raise RuntimeError(f"K_1 has dimension {len(tails[1])}, expected {m - 1}")
    out: list[np.ndarray | None] = [None] * (m + 1)
    for l in range(2, m + 1):
        smaller = tails[l]
        for x in tails[l - 1]:
            if independent_append(smaller, x) is not None:
                out[l] = x.copy()
                break
        if out[l] is None:
            raise RuntimeError(f"could not isolate input layer {l}")
    if ordered_input_dimension := expected_vinegar + m:
        if tails[1].shape[1] != ordered_input_dimension:
            raise RuntimeError("tail ambient dimension mismatch")
    return out


def solve_triangular_map(
    ordered: QuadraticMap,
    target: np.ndarray,
    tails: list[np.ndarray],
    directions: list[np.ndarray | None],
    rng: np.random.Generator,
    max_attempts: int = 10000,
) -> tuple[np.ndarray, int]:
    """Invert an equivalent one-variable-per-layer triangular map."""
    free = complement_standard_columns(tails[1], ordered.n)
    if len(free) != ordered.n - len(tails[1]):
        raise RuntimeError("bad first-layer complement")

    for attempt in range(1, max_attempts + 1):
        # Find a point in the first quotient hitting target[0].
        for _ in range(128):
            x = np.zeros(ordered.n, dtype=np.uint8)
            x[free] = rng.integers(0, 16, size=len(free), dtype=np.uint8)
            if QuadraticMap.eval_form(ordered.polars[0], ordered.diags[0], x) == target[0]:
                break
        else:
            continue

        ok = True
        for l in range(2, ordered.m + 1):
            w = directions[l]
            assert w is not None
            choices = []
            for a in range(16):
                cand = x ^ MUL[a, w]
                value = QuadraticMap.eval_form(
                    ordered.polars[l - 1], ordered.diags[l - 1], cand
                )
                if value == target[l - 1]:
                    choices.append(a)
            if not choices:
                ok = False
                break
            a = int(choices[int(rng.integers(0, len(choices)))])
            x ^= MUL[a, w]

        if ok and np.array_equal(ordered.evaluate(x), target):
            return x, attempt
    raise RuntimeError("triangular inversion attempt budget exhausted")


def solve_linear(a: np.ndarray, b: np.ndarray) -> np.ndarray | None:
    """Solve a*x=b; return one solution or None."""
    aug = np.concatenate((a.copy(), b[:, None]), axis=1)
    nr, nc = a.shape
    row = 0
    pivots: list[int] = []
    for col in range(nc):
        nz = np.flatnonzero(aug[row:, col])
        if not len(nz):
            continue
        p = row + int(nz[0])
        if p != row:
            aug[[row, p]] = aug[[p, row]]
        aug[row] = MUL[INV[aug[row, col]], aug[row]]
        factors = aug[:, col].copy()
        factors[row] = 0
        active = np.flatnonzero(factors)
        if len(active):
            aug[active] ^= MUL[factors[active, None], aug[row][None, :]]
        pivots.append(col)
        row += 1
        if row == nr:
            break
    for r in range(row, nr):
        if not np.any(aug[r, :nc]) and aug[r, nc]:
            return None
    x = np.zeros(nc, dtype=np.uint8)
    for r, col in enumerate(pivots):
        x[col] = aug[r, nc]
    return x

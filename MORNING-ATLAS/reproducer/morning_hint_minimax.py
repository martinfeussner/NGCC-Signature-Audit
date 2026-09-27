#!/usr/bin/env python3
"""Minimax recovery of MORNING-ATLAS t0 from public hint observations."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import numpy as np
from scipy.optimize import linprog
from scipy.sparse import coo_matrix, csr_matrix, hstack, vstack


HEADER = struct.Struct("<8sIIIIQ")


def load(path: Path):
    data = path.read_bytes()
    magic, n, k, kappa, pkbytes, signatures = HEADER.unpack_from(data)
    if magic.rstrip(b"\0") != b"ATLHNT1":
        raise ValueError("bad observation magic")
    offset = HEADER.size + pkbytes
    dtype = np.dtype([("c", "i1", (n,)), ("u", "<i2", (k, n))], align=False)
    records = np.frombuffer(data, dtype=dtype, count=signatures, offset=offset)
    if offset + signatures * dtype.itemsize != len(data):
        raise ValueError("observation file size mismatch")
    return n, k, kappa, signatures, records


class NegacyclicDesign:
    def __init__(self, challenges: np.ndarray):
        self.challenges = challenges.astype(np.float64, copy=False)
        self.signatures, self.n = self.challenges.shape
        self.challenge_fft = np.fft.rfft(self.challenges, n=2 * self.n, axis=1)

    def apply(self, secret: np.ndarray, *, integer: bool = False) -> np.ndarray:
        """Return every C_s*secret row using batched FFT convolution."""
        secret_fft = np.fft.rfft(secret.astype(np.float64), n=2 * self.n)
        ordinary = np.fft.irfft(self.challenge_fft * secret_fft, n=2 * self.n, axis=1)
        negacyclic = ordinary[:, : self.n] - ordinary[:, self.n :]
        # LP iterates are real, so rounding here changes the separation oracle.
        # Integer candidates, in contrast, should be snapped past FFT noise.
        return np.rint(negacyclic) if integer else negacyclic

    def selected_rows(self, flat_indices: np.ndarray) -> csr_matrix:
        dense = np.zeros((len(flat_indices), self.n), dtype=np.float64)
        for out, flat in enumerate(flat_indices):
            signature, j = divmod(int(flat), self.n)
            c = self.challenges[signature]
            for i in np.flatnonzero(c):
                if j >= i:
                    d, sign = j - i, 1
                else:
                    d, sign = j + self.n - i, -1
                dense[out, d] = sign * c[i]
        return csr_matrix(dense)


def score(label: str, estimate: np.ndarray, truth: np.ndarray | None):
    fields = [label, f"min={estimate.min():.3f}", f"max={estimate.max():.3f}"]
    if truth is not None:
        err = estimate - truth
        fields.extend(
            [
                f"rmse={np.sqrt(np.mean(err*err)):.6f}",
                f"max_error={np.max(np.abs(err)):.6f}",
                f"rounded_exact={np.count_nonzero(np.rint(estimate)==truth)}/{truth.size}",
            ]
        )
    print(" ".join(fields), flush=True)


def minimax_cutting_plane(design: NegacyclicDesign, u_matrix, bounds, initial=2048, batch=2048):
    """Solve min_t max_i |X_i t-u_i| without materializing both full LP halves."""
    n = design.n
    u = u_matrix.reshape(-1)
    selected = set(np.argpartition(np.abs(u), -min(initial, len(u)))[-min(initial, len(u)):].tolist())

    objective = np.zeros(n + 1)
    objective[-1] = 1
    for iteration in range(50):
        index = np.fromiter(sorted(selected), dtype=np.int64)
        xs = design.selected_rows(index)
        ones = coo_matrix((-np.ones(len(index)), (np.arange(len(index)), np.zeros(len(index)))),
                          shape=(len(index), 1)).tocsr()
        aub = vstack([hstack([xs, ones]), hstack([-xs, ones])]).tocsr()
        us = u[index]
        result = linprog(
            objective,
            A_ub=aub,
            b_ub=np.concatenate([us, -us]),
            bounds=bounds,
            method="highs",
        )
        if not result.success:
            return None, iteration, len(selected)
        estimate = result.x[:-1]
        radius = result.x[-1]
        residual = design.apply(estimate).reshape(-1) - u
        absolute = np.abs(residual)
        max_residual = float(absolute.max())
        print(
            f"  cut={iteration} selected={len(selected)} lp_radius={radius:.6f} full_radius={max_residual:.6f}",
            flush=True,
        )
        violating = np.flatnonzero(absolute > radius + 1e-4)
        if not len(violating):
            return result, iteration + 1, len(selected)
        take = violating[np.argpartition(absolute[violating], -min(batch, len(violating)))[-min(batch, len(violating)):]]
        old_size = len(selected)
        selected.update(take.tolist())
        if len(selected) == old_size:
            return result, iteration + 1, len(selected)
    return result, 50, len(selected)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("observations", type=Path)
    ap.add_argument("--secret", type=Path)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    n, k, kappa, signatures, records = load(args.observations)
    if args.limit is not None:
        records = records[: args.limit]
        signatures = len(records)
    truth = None if args.secret is None else np.loadtxt(args.secret).reshape(k, n)
    print(f"signatures={signatures} n={n} k={k} kappa={kappa}", flush=True)
    design = NegacyclicDesign(records["c"])
    # decompose_keygen represents the low part in ]-2^(d-1), 2^(d-1)],
    # hence the asymmetric integer support {-511,...,512} for d=10.
    bounds = [(-511, 512)] * n + [(0, None)]
    estimates = []
    for p in range(k):
        u = records["u"][:, p, :].astype(np.float64)
        result, iterations, selected = minimax_cutting_plane(design, u, bounds)
        if result is None or not result.success:
            print(f"poly={p} FAIL cutting-plane LP")
            continue
        estimate = result.x[:-1]
        estimates.append(estimate)
        rounded = np.rint(estimate)
        rounded_residual = design.apply(rounded, integer=True) - u
        rounded_absolute = np.abs(rounded_residual)
        score(
            f"poly={p} optimum_radius={result.x[-1]:.6f} cuts={iterations} selected={selected}",
            estimate,
            None if truth is None else truth[p],
        )
        print(
            f"poly={p} rounded_public_max_residual={rounded_absolute.max():.0f} "
            f"rounded_public_violations={np.count_nonzero(rounded_absolute > 8183)}",
            flush=True,
        )
    if truth is not None and len(estimates) == k:
        score("all", np.vstack(estimates), truth)
    if args.output is not None and len(estimates) == k:
        np.savez(
            args.output,
            continuous=np.vstack(estimates),
            rounded=np.rint(np.vstack(estimates)).astype(np.int16),
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recover high-confidence UVW coordinate pairs from public signature errors."""

import argparse
import struct
import time

import numpy as np


def read_errors(path, limit=None):
    with open(path, "rb") as f:
        nsig, n = struct.unpack("<II", f.read(8))
        raw = np.fromfile(f, dtype=np.uint8, count=nsig * n)
    if raw.size != nsig * n:
        raise ValueError("truncated error-vector file")
    errors = raw.reshape(nsig, n)
    return errors if limit is None else errors[:limit]


def public_log_weights(n, k1, k2, weight):
    half = n / 2
    alpha = k1 / half
    beta = 1 - alpha

    # Dec_Z: a coordinate is in the k2 free positions with probability k2/half;
    # t is uniform on 0..k2, so its mean nonzero probability there is 1/2.
    # A solved coordinate is uniform in F_3 under the random-code model.
    e2_nonzero = (k2 / half) * 0.5 + ((half - k2) / half) * (2 / 3)
    e2_zero = 1 - e2_nonzero

    # Normalize the more likely hidden relation to y=x.  Information-set
    # coordinates are always nonzero; solved coordinates use the random-code
    # model.  This distribution is entirely parameter-derived.
    p = np.array(
        [
            [beta * e2_zero / 3, beta * e2_nonzero / 6, beta * e2_nonzero / 6],
            [
                beta * e2_nonzero / 6,
                alpha * e2_nonzero / 2 + beta * e2_nonzero / 6,
                alpha * e2_zero / 2 + beta * e2_zero / 3,
            ],
            [
                beta * e2_nonzero / 6,
                alpha * e2_zero / 2 + beta * e2_zero / 3,
                alpha * e2_nonzero / 2 + beta * e2_nonzero / 6,
            ],
        ],
        dtype=np.float64,
    )
    p0 = (n - weight) / n
    marginal = np.array([p0, (1 - p0) / 2, (1 - p0) / 2])
    null = np.outer(marginal, marginal)
    return np.log(p / null).astype(np.float32), p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("errors")
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--block", type=int, default=128)
    ap.add_argument("--min-margin", type=float, default=0.0)
    ap.add_argument("--min-relation-gap", type=float, default=0.0)
    ap.add_argument("--k1", type=int, default=3250)
    ap.add_argument("--k2", type=int, default=1600)
    ap.add_argument("--weight", type=int, default=8633)
    args = ap.parse_args()

    errors = read_errors(args.errors, args.limit)
    nsig, n = errors.shape
    weights, model = public_log_weights(n, args.k1, args.k2, args.weight)
    print(f"signatures={nsig} coordinates={n}")
    print("parameter_model=" + np.array2string(model, precision=8))

    indicators = [(errors == x).astype(np.float32) for x in range(3)]
    neg = np.array([0, 2, 1])
    value = []
    value_neg = []
    for x in range(3):
        v = np.empty_like(errors, dtype=np.float32)
        vn = np.empty_like(errors, dtype=np.float32)
        for y in range(3):
            v[errors == y] = weights[x, y]
            vn[errors == y] = weights[x, neg[y]]
        value.append(v)
        value_neg.append(vn)

    best = np.empty(n, dtype=np.int32)
    relation = np.empty(n, dtype=np.uint8)
    best_score = np.empty(n, dtype=np.float32)
    second_score = np.empty(n, dtype=np.float32)
    relation_gap = np.empty(n, dtype=np.float32)
    started = time.monotonic()
    for lo in range(0, n, args.block):
        hi = min(n, lo + args.block)
        plus = np.zeros((hi - lo, n), dtype=np.float32)
        minus = np.zeros_like(plus)
        for x in range(3):
            plus += indicators[x][:, lo:hi].T @ value[x]
            minus += indicators[x][:, lo:hi].T @ value_neg[x]
        score = np.maximum(plus, minus)
        row = np.arange(hi - lo)
        score[row, np.arange(lo, hi)] = -np.inf
        chosen = np.argmax(score, axis=1)
        best[lo:hi] = chosen
        best_score[lo:hi] = score[row, chosen]
        relation[lo:hi] = np.where(
            plus[row, chosen] >= minus[row, chosen], 1, 2
        )
        relation_gap[lo:hi] = np.abs(plus[row, chosen] - minus[row, chosen])
        second_score[lo:hi] = np.partition(score, -2, axis=1)[:, -2]
        if hi == n or hi % (10 * args.block) == 0:
            print(f"processed={hi}/{n} elapsed={time.monotonic()-started:.1f}s", flush=True)

    index = np.arange(n)
    mutual = index == best[best]
    left = np.where(mutual & (index < best))[0]
    pair_margin = np.minimum(
        best_score[left] - second_score[left],
        best_score[best[left]] - second_score[best[left]],
    )
    pair_relation_gap = np.minimum(relation_gap[left], relation_gap[best[left]])
    keep = (pair_margin >= args.min_margin) & (
        pair_relation_gap >= args.min_relation_gap
    )
    left = left[keep]
    order = np.argsort(best_score[left])[::-1]
    left = left[order]

    with open(args.out, "w") as f:
        f.write("left\tright\tdominant_ratio\tscore\tmargin\trelation_gap\n")
        for a in left:
            b = int(best[a])
            margin = min(float(best_score[a] - second_score[a]), float(best_score[b] - second_score[b]))
            f.write(
                f"{a}\t{b}\t{int(relation[a])}\t"
                f"{float(best_score[a]):.9g}\t{margin:.9g}\t"
                f"{min(float(relation_gap[a]), float(relation_gap[b])):.9g}\n"
            )
    print(f"mutual_pairs={left.size} output={args.out}")

if __name__ == "__main__":
    main()

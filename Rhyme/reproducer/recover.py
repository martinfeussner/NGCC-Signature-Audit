#!/usr/bin/env python3
"""Recover Rhyme's secret tail from public (challenge, z_bottom) records."""
import argparse
from pathlib import Path
import numpy as np

N = 256
D = 4
RECORD_BYTES = N + 2 * D * N


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix")
    ap.add_argument("--gamma", type=float, required=True,
                    help="coefficient in z_bottom = noise + gamma*s_tail*c")
    ap.add_argument("--train", type=int, default=40000)
    ap.add_argument("--counts", default="1000,5000,10000,20000,30000,40000")
    args = ap.parse_args()

    raw = np.memmap(args.prefix + ".records", dtype=np.uint8, mode="r")
    total = raw.size // RECORD_BYTES
    if total < args.train:
        raise SystemExit(f"only {total} records, need {args.train}")
    raw = raw[: total * RECORD_BYTES].reshape(total, RECORD_BYTES)
    c = np.asarray(raw[:, :N], dtype=np.float64)
    zb_u8 = np.asarray(raw[:, N:]).copy()
    zb = zb_u8.reshape(-1).view("<i2").reshape(total, D, N).astype(np.float64)
    truth_path = Path(args.prefix + ".secret")
    truth = (np.fromfile(truth_path, dtype="<i2").reshape(D, N)
             if truth_path.exists() else None)

    # Evaluating at odd 2N-th roots diagonalizes negacyclic convolution.
    twist = np.exp(-1j * np.pi * np.arange(N) / N)
    chat = np.fft.fft(c * twist, axis=1)
    zhat = np.fft.fft(zb * twist[None, None, :], axis=2)

    requested = [int(x) for x in args.counts.split(",")]
    counts = sorted(set(x for x in requested + [args.train] if x <= args.train))
    final = None
    for t in counts:
        den = np.sum(np.abs(chat[:t]) ** 2, axis=0)
        num = np.einsum("tk,trk->rk", np.conj(chat[:t]), zhat[:t])
        shat = num / (args.gamma * den[None, :])
        sest = (np.fft.ifft(shat, axis=1) / twist[None, :]).real
        rounded = np.rint(sest).astype(np.int16)
        if truth is None:
            print(f"T={t} rounded_linf={np.max(np.abs(rounded))}")
        else:
            err = sest - truth
            exact = int(np.sum(rounded == truth))
            print(f"T={t} rmse={np.sqrt(np.mean(err*err)):.6f} "
                  f"maxerr={np.max(np.abs(err)):.6f} exact={exact}/{D*N}")
        if t == args.train:
            final = rounded

    assert final is not None
    final.astype("<i2").tofile(args.prefix + ".recovered")

    # Honest held-out prediction control.  It is not used for fitting.
    if total > args.train:
        lo = args.train
        pred_hat = args.gamma * chat[lo:, None, :] * np.fft.fft(
            final * twist[None, :], axis=1)[None, :, :]
        pred = (np.fft.ifft(pred_hat, axis=2) /
                twist[None, None, :]).real
        residual = zb[lo:] - pred
        zero_residual = zb[lo:]
        perturbed = final.astype(np.float64)
        perturbed[0, 0] += 1
        pert_hat = args.gamma * chat[lo:, None, :] * np.fft.fft(
            perturbed * twist[None, :], axis=1)[None, :, :]
        pert_pred = (np.fft.ifft(pert_hat, axis=2) /
                     twist[None, None, :]).real
        pert_residual = zb[lo:] - pert_pred
        print(f"heldout={total-lo} residual_rms={np.sqrt(np.mean(residual**2)):.6f} "
              f"zero_model_rms={np.sqrt(np.mean(zero_residual**2)):.6f} "
              f"perturbed_rms={np.sqrt(np.mean(pert_residual**2)):.6f}")


if __name__ == "__main__":
    main()

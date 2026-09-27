#!/usr/bin/env python3
"""Recover the submitted VDOO-128 implementation's hidden O2 space.

Only the public key is used by the recovery routine.  When this script creates
a fresh test key, it keeps the generated secret key in memory long enough to
check that the recovered 40-dimensional space is exactly the real hidden O2
space.  That comparison is validation, not an input to the attack.
"""

from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import time

import numpy as np

from vdoo_rankone_toy import (
    gf_rank_rref,
    normalize_line,
    recover_rank_one_lines,
    same_rowspace,
)


Q = 16
V = 67
D = 16
O1 = 14
O2 = 40
N = V + D + O1 + O2
M = D + O1 + O2
N_BYTES = (N + 1) // 2
M_BYTES = (M + 1) // 2
PK_BYTES = M * N * (N + 1) // 4
SK_BYTES = 32 + M_BYTES * M + N_BYTES * N + PK_BYTES


def unpack_nibbles(buf: bytes, count: int) -> np.ndarray:
    raw = np.frombuffer(buf, dtype=np.uint8)
    out = np.empty(2 * len(raw), dtype=np.uint8)
    out[0::2] = raw & 0x0F
    out[1::2] = raw >> 4
    return out[:count]


def generate_submitted_key(lib_path: Path) -> tuple[bytes, bytes]:
    lib = ctypes.CDLL(str(lib_path))
    lib.sig_get_pk_len_bytes.restype = ctypes.c_ulonglong
    lib.sig_get_sk_len_bytes.restype = ctypes.c_ulonglong
    assert lib.sig_get_pk_len_bytes() == PK_BYTES
    assert lib.sig_get_sk_len_bytes() == SK_BYTES

    pk = (ctypes.c_ubyte * PK_BYTES)()
    sk = (ctypes.c_ubyte * SK_BYTES)()
    pk_len = ctypes.c_ulonglong()
    sk_len = ctypes.c_ulonglong()
    lib.sig_keygen.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    rc = lib.sig_keygen(pk, ctypes.byref(pk_len), sk, ctypes.byref(sk_len))
    if rc != 0 or pk_len.value != PK_BYTES or sk_len.value != SK_BYTES:
        raise RuntimeError(f"sig_keygen failed: rc={rc}")
    return bytes(pk), bytes(sk)


def public_polars(pk: bytes) -> np.ndarray:
    if len(pk) != PK_BYTES:
        raise ValueError(f"wrong public-key length: {len(pk)}")
    out = np.zeros((M, N, N), dtype=np.uint8)
    monom = 0
    for i in range(N):
        for j in range(i, N):
            coeff = unpack_nibbles(pk[monom * M_BYTES : (monom + 1) * M_BYTES], M)
            if i != j:
                out[:, i, j] = coeff
                out[:, j, i] = coeff
            monom += 1
    assert monom == N * (N + 1) // 2
    return out


def secret_o2_basis(sk: bytes) -> np.ndarray:
    """Extract public-coordinate O2 solely for a post-attack correctness check."""
    invt_off = 32 + M_BYTES * M
    invt = sk[invt_off : invt_off + N_BYTES * N]
    cols = []
    for j in range(N):
        cols.append(unpack_nibbles(invt[j * N_BYTES : (j + 1) * N_BYTES], N))
    invt_matrix = np.stack(cols, axis=1)
    return invt_matrix[:, V + D + O1 :].T.copy()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pk", type=Path, help="attack an existing raw public key")
    parser.add_argument("--trials", type=int, default=4)
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    lib_path = here.parent / "ngcc-harness/sign-33/lib/libvdoo_128.so"

    sk = None
    if args.pk:
        pk = args.pk.read_bytes()
    else:
        t0 = time.perf_counter()
        pk, sk = generate_submitted_key(lib_path)
        print(f"generated submitted VDOO-128 key in {time.perf_counter() - t0:.2f}s")

    t0 = time.perf_counter()
    polars = public_polars(pk)
    print(f"parsed {M} public polar matrices in {time.perf_counter() - t0:.2f}s")

    rng = np.random.default_rng(0x56444F4F128)
    t0 = time.perf_counter()
    lines = recover_rank_one_lines(polars, rng, trials=args.trials)
    elapsed = time.perf_counter() - t0
    unique = {normalize_line(x) for x in lines}
    got = np.stack(lines) if lines else np.zeros((0, N), dtype=np.uint8)
    got_rank = gf_rank_rref(got)[0] if len(got) else 0

    print(f"public-only recovery time: {elapsed:.2f}s")
    print(f"verified rank-one derivative lines: {len(unique)}")
    print(f"their span dimension: {got_rank} (expected O2 dimension {O2})")

    if sk is not None:
        expected = secret_o2_basis(sk)
        exact = same_rowspace(got, expected)
        print(f"validation against hidden test key: exact O2 recovery = {exact}")
        if not exact:
            raise SystemExit(1)

    if got_rank != O2:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

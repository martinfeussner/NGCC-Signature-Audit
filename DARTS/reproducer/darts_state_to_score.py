#!/usr/bin/env python3
"""Convert an atomic DARTS public accumulator checkpoint into a score blob."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import struct

import numpy as np


N = 512
POLYS = 2
PUBLIC_KEY_BYTES = 1120
STATE_HEADER = struct.Struct("<8sIIQQQQ")
SCORE_HEADER = struct.Struct("<8sIIQ")
STATE_BYTES = STATE_HEADER.size + PUBLIC_KEY_BYTES + (POLYS + 1) * N * 8
SCORE_BYTES = SCORE_HEADER.size + PUBLIC_KEY_BYTES + POLYS * N * 8


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    parser.add_argument("score", type=Path)
    parser.add_argument("--require-signatures", type=int)
    parser.add_argument(
        "--subtract-state",
        type=Path,
        help="solve the independent accumulator segment after this earlier state",
    )
    args = parser.parse_args()

    raw = args.state.read_bytes()
    if len(raw) != STATE_BYTES:
        raise SystemExit(f"invalid state length: {len(raw)}")
    magic, n, polys, signatures, attempts, branch0, branch1 = (
        STATE_HEADER.unpack_from(raw)
    )
    if magic.rstrip(b"\0") != b"DARTST2" or n != N or polys != POLYS:
        raise SystemExit("invalid state header")
    if (args.require_signatures is not None
            and signatures != args.require_signatures):
        raise SystemExit(
            f"checkpoint has {signatures}, expected {args.require_signatures}"
        )

    off = STATE_HEADER.size
    public_key = raw[off:off + PUBLIC_KEY_BYTES]
    off += PUBLIC_KEY_BYTES
    acc = np.frombuffer(raw, dtype="<i8", count=POLYS * N, offset=off)
    acc = acc.reshape(POLYS, N).copy()
    off += POLYS * N * 8
    gram = np.frombuffer(raw, dtype="<i8", count=N, offset=off).copy()

    if args.subtract_state is not None:
        earlier = args.subtract_state.read_bytes()
        if len(earlier) != STATE_BYTES:
            raise SystemExit(f"invalid earlier state length: {len(earlier)}")
        emagic, en, epolys, esignatures, eattempts, ebranch0, ebranch1 = (
            STATE_HEADER.unpack_from(earlier)
        )
        eoff = STATE_HEADER.size
        epublic_key = earlier[eoff:eoff + PUBLIC_KEY_BYTES]
        eoff += PUBLIC_KEY_BYTES
        if (
            emagic.rstrip(b"\0") != b"DARTST2"
            or en != N
            or epolys != POLYS
            or epublic_key != public_key
            or esignatures >= signatures
        ):
            raise SystemExit("incompatible earlier accumulator state")
        eacc = np.frombuffer(
            earlier, dtype="<i8", count=POLYS * N, offset=eoff
        ).reshape(POLYS, N)
        eoff += POLYS * N * 8
        egram = np.frombuffer(earlier, dtype="<i8", count=N, offset=eoff)
        acc -= eacc
        gram -= egram
        signatures -= esignatures
        attempts -= eattempts
        branch0 -= ebranch0
        branch1 -= ebranch1

    rows = np.arange(N)[:, None]
    cols = np.arange(N)[None, :]
    indices = (rows - cols) % N
    signs = np.where(rows >= cols, 1.0, -1.0)
    matrix = signs * gram[indices]
    theta = np.linalg.solve(matrix, acc.T.astype(np.float64)).T

    output = bytearray()
    output += SCORE_HEADER.pack(b"DARTS02\0", N, POLYS, signatures)
    output += public_key
    output += theta.astype("<f8", copy=False).tobytes(order="C")
    if len(output) != SCORE_BYTES:
        raise AssertionError((len(output), SCORE_BYTES))
    tmp = args.score.with_name(args.score.name + ".tmp")
    tmp.write_bytes(output)
    os.replace(tmp, args.score)
    print(
        f"signatures={signatures} attempts={attempts} "
        f"branches={branch0},{branch1} score={args.score} bytes={len(output)}"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Merge disjoint MORNING public response-constraint shards."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


HEADER = struct.Struct("<8sIIIIQQ")


def metadata(path: Path):
    with path.open("rb") as stream:
        raw = stream.read(HEADER.size)
        if len(raw) != HEADER.size:
            raise ValueError(f"short header in {path}")
        fields = HEADER.unpack(raw)
        magic, n, ell, kappa, pkbytes, signatures, constraints = fields
        if magic.rstrip(b"\0") != b"ATLCON1":
            raise ValueError(f"unexpected magic in {path}")
        public_key = stream.read(pkbytes)
        if len(public_key) != pkbytes:
            raise ValueError(f"short public key in {path}")
    row_size = 4 + n
    expected = HEADER.size + pkbytes + constraints * row_size
    actual = path.stat().st_size
    if actual != expected:
        raise ValueError(f"size mismatch in {path}: expected {expected}, got {actual}")
    return fields, public_key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()

    first_fields, first_key = metadata(args.inputs[0])
    magic, n, ell, kappa, pkbytes, _, _ = first_fields
    total_signatures = 0
    total_constraints = 0
    entries = []
    for path in args.inputs:
        fields, public_key = metadata(path)
        pmagic, pn, pell, pkappa, ppkbytes, signatures, constraints = fields
        if (pmagic, pn, pell, pkappa, ppkbytes, public_key) != (
            magic,
            n,
            ell,
            kappa,
            pkbytes,
            first_key,
        ):
            raise ValueError(f"incompatible shard {path}")
        total_signatures += signatures
        total_constraints += constraints
        entries.append((path, constraints))

    with args.output.open("wb") as output:
        output.write(
            HEADER.pack(
                magic,
                n,
                ell,
                kappa,
                pkbytes,
                total_signatures,
                total_constraints,
            )
        )
        output.write(first_key)
        for path, constraints in entries:
            with path.open("rb") as source:
                source.seek(HEADER.size + pkbytes)
                while chunk := source.read(8 << 20):
                    output.write(chunk)
            print(
                f"included={path} constraints={constraints}",
                flush=True,
            )
    print(
        f"output={args.output} signatures={total_signatures} "
        f"constraints={total_constraints} bytes={args.output.stat().st_size}",
        flush=True,
    )


if __name__ == "__main__":
    main()

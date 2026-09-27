#!/usr/bin/env python3
"""Serialize one integer array from an NPZ file as one signed value per line."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("key")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    values = np.load(args.input)[args.key]
    rounded = np.rint(values).astype(np.int64)
    args.output.write_text("".join(f"{int(value)}\n" for value in rounded.ravel()))


if __name__ == "__main__":
    main()

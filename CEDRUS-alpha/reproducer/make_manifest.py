#!/usr/bin/env python3
"""Regenerate the immutable source/input manifest."""

from __future__ import annotations

import hashlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
EXCLUDED={"IMMUTABLE.SHA256SUMS","SHA256SUMS"}
EXCLUDED_TOP={"work","build","__pycache__"}


def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1 << 20),b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    rows=[]
    for path in sorted(HERE.rglob("*")):
        rel=path.relative_to(HERE)
        if not path.is_file() or rel.name in EXCLUDED or rel.parts[0] in EXCLUDED_TOP:
            continue
        rows.append(f"{digest(path)}  {rel.as_posix()}")
    (HERE/"IMMUTABLE.SHA256SUMS").write_text("\n".join(rows)+"\n")


if __name__ == "__main__":
    main()

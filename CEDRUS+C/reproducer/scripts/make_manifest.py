#!/usr/bin/env python3
"""Regenerate SHA256SUMS for immutable release inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "SHA256SUMS"


def excluded(path: Path) -> bool:
    if path == MANIFEST or not path.is_file():
        return True
    rel = path.relative_to(ROOT)
    if "__pycache__" in rel.parts or path.suffix == ".pyc":
        return True
    if rel.parts[0] in {"build", "work"}:
        return True
    if len(rel.parts) >= 2 and rel.parts[:2] == ("results", "latest"):
        return True
    return False


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    entries = []
    for path in sorted(ROOT.rglob("*")):
        if not excluded(path):
            entries.append(f"{digest(path)}  {path.relative_to(ROOT).as_posix()}")
    for name in ("CEDRUS+C_Attack_Description.tex", "CEDRUS+C_Attack_Description.pdf"):
        path = ROOT.parent / name
        entries.append(f"{digest(path)}  ../{name}")
    MANIFEST.write_text("\n".join(entries) + "\n")
    print(f"manifest_entries={len(entries)}")


if __name__ == "__main__":
    main()

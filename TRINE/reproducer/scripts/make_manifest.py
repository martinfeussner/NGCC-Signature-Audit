#!/usr/bin/env python3
import hashlib
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


rows = []
for path in sorted(p for p in BASE.rglob("*") if p.is_file()):
    rel = path.relative_to(BASE)
    if rel.as_posix() == "SHA256SUMS":
        continue
    if rel.parts[0] in {"bin"} or rel.parts[:2] == ("results", "latest"):
        continue
    if "__pycache__" in rel.parts or path.suffix in {".pyc", ".pyo"}:
        continue
    rows.append(f"{digest(path)}  {rel.as_posix()}")
(BASE / "SHA256SUMS").write_text("\n".join(rows) + "\n")
print(f"manifest_entries={len(rows)}")


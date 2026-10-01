#!/usr/bin/env python3
"""Create a stable source/evidence manifest, excluding compiled executables."""

from hashlib import sha256
from pathlib import Path

root = Path(__file__).resolve().parent
entries = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or path.name in {"SHA256SUMS", "manifest-check.txt"}:
        continue
    data = path.read_bytes()
    if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
        continue
    relative = path.relative_to(root).as_posix()
    entries.append(f"{sha256(data).hexdigest()}  {relative}\n")

(root / "SHA256SUMS").write_text("".join(entries))
print(f"wrote {len(entries)} entries")

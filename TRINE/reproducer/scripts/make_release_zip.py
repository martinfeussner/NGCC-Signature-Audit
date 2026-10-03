#!/usr/bin/env python3
"""Create a byte-reproducible release archive with normalized metadata."""

from __future__ import annotations

import argparse
import stat
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
FIXED_TIME = (2026, 10, 3, 0, 0, 0)


def included(path: Path) -> bool:
    rel = path.relative_to(BASE)
    if not path.is_file():
        return False
    if rel.parts[:1] == ("bin",) or rel.parts[:2] == ("results", "latest"):
        return False
    if "__pycache__" in rel.parts or path.suffix in {".pyc", ".pyo"}:
        return False
    return True


parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
args = parser.parse_args()
output = args.output.resolve()
output.parent.mkdir(parents=True, exist_ok=True)

files = sorted(path for path in BASE.rglob("*") if included(path))
with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files:
        rel = path.relative_to(BASE)
        info = zipfile.ZipInfo(f"reproducer/{rel.as_posix()}", FIXED_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        mode = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
        info.external_attr = (stat.S_IFREG | mode) << 16
        archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                         compresslevel=9)

print(f"archive_files={len(files)}")
print(f"archive_path={output}")

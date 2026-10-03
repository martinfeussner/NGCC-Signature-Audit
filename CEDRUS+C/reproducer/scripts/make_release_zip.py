#!/usr/bin/env python3
"""Build the normalized CEDRUS+C disclosure archive."""

from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path


RELEASE = Path(__file__).resolve().parents[2]
OUTPUT = RELEASE / "CEDRUS+C_FORS_Accumulation_Reproducer.zip"
ARCHIVE_ROOT = "CEDRUS+C_FORS_Accumulation"


def excluded(path: Path) -> bool:
    rel = path.relative_to(RELEASE)
    if path == OUTPUT:
        return True
    if rel.name in {
        "CEDRUS+C_Attack_Description.aux",
        "CEDRUS+C_Attack_Description.log",
        "CEDRUS+C_Attack_Description.out",
    }:
        return True
    parts = rel.parts
    if "__pycache__" in parts:
        return True
    if len(parts) >= 2 and parts[0] == "reproducer" and parts[1] in {
        "build",
        "work",
    }:
        return True
    if len(parts) >= 3 and parts[:3] == ("reproducer", "results", "latest"):
        return True
    return path.suffix == ".pyc"


def main() -> None:
    files = sorted(path for path in RELEASE.rglob("*") if path.is_file() and not excluded(path))
    temporary = OUTPUT.with_suffix(".zip.tmp")
    with zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in files:
            rel = path.relative_to(RELEASE).as_posix()
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{rel}", (2026, 10, 3, 0, 0, 0))
            mode = 0o755 if os.access(path, os.X_OK) else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    temporary.replace(OUTPUT)
    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f"{digest}  {OUTPUT.name}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Replay SPEC_REPAIRS.patch from the exact submitted CRLF source bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent.parent
PRISTINE = HERE / "vendor" / "submitted-pristine-256f"
EXPECTED = HERE / "vendor" / "spec-repaired-256f"
PATCH = HERE / "SPEC_REPAIRS.patch"


def tree_hash(root: Path, excluded: set[str] | None = None) -> tuple[str, int]:
    excluded = excluded or set()
    h = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or rel in excluded:
            continue
        data = path.read_bytes()
        h.update(rel.encode("utf-8") + b"\0")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
        count += 1
    return h.hexdigest(), count


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    workspace = args.output
    replayed = workspace / "submitted-256f"
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(PRISTINE, replayed)

    pristine_address = (replayed / "address.c").read_bytes()
    pristine_thash = (replayed / "thash_sm3_simple.c").read_bytes()
    assert b"\r\n" in pristine_address
    assert b"\r\n" in pristine_thash
    assert not pristine_thash.endswith((b"\n", b"\r"))

    # The submitted C/H files use CRLF.  Normalize only line endings; preserve
    # the submitted presence/absence of the final newline.  GNU patch needs a
    # line boundary for the final thash hunk, so append that one boundary
    # explicitly before applying the textual patch.
    for path in sorted(replayed.rglob("*")):
        if path.is_file() and path.suffix in {".c", ".h"}:
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
    thash = replayed / "thash_sm3_simple.c"
    if not thash.read_bytes().endswith(b"\n"):
        thash.write_bytes(thash.read_bytes() + b"\n")

    proc = subprocess.run(
        ["patch", "--batch", "--forward", "--strip=0", "--input", str(PATCH)],
        cwd=workspace,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit("patch replay failed:\n" + proc.stdout)

    compared = 0
    for expected in sorted(EXPECTED.rglob("*")):
        if not expected.is_file() or expected.name == "native_check.c":
            continue
        rel = expected.relative_to(EXPECTED)
        actual = replayed / rel
        if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
            raise SystemExit(f"replayed source mismatch: {rel}")
        compared += 1

    pristine_digest, pristine_count = tree_hash(PRISTINE)
    repaired_digest, repaired_count = tree_hash(EXPECTED, {"native_check.c"})
    replayed_digest, replayed_count = tree_hash(replayed, {"Makefile"})
    # EXPECTED omits the submitted Makefile and adds only native_check.c;
    # removing those two release-local files makes the trees identical.
    assert repaired_digest == replayed_digest
    assert repaired_count == replayed_count == compared

    result = {
        "status": "PASS",
        "pristine_files": pristine_count,
        "compared_repaired_files": compared,
        "pristine_tree_sha256": pristine_digest,
        "repaired_tree_sha256": repaired_digest,
        "replayed_tree_sha256": replayed_digest,
        "observed_pristine_crlf": True,
        "observed_pristine_thash_missing_final_newline": True,
        "normalization": "CRLF-to-LF for C/H; append final LF to thash_sm3_simple.c",
        "patch_applied": "SPEC_REPAIRS.patch",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

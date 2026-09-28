"""Find the first successful public refinement checkpoint in fixed stream order."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


STEP = 100_000
PER_STREAM = 500_000
SUCCESS = "equivalent_key_fresh_forgery=ACCEPT"


def state_at(base: Path, count: int) -> Path:
    return base if count == PER_STREAM else Path(f"{base}.{count}")


def states_for_total(bases: list[Path], total: int) -> list[Path]:
    full, remainder = divmod(total, PER_STREAM)
    selected = bases[:full]
    if remainder:
        if full >= len(bases):
            raise ValueError("refinement total exceeds supplied streams")
        selected = [*selected, state_at(bases[full], remainder)]
    return selected


def main() -> int:
    if len(sys.argv) < 5:
        print(
            "usage: scan_public_ladder.py BINARY RESULT PREVIOUS_RESULT "
            "STATE_BASE [STATE_BASE ...]",
            file=sys.stderr,
        )
        return 2

    binary = Path(sys.argv[1]).resolve()
    result_path = Path(sys.argv[2]).resolve()
    previous_path = Path(sys.argv[3]).resolve()
    bases = [Path(arg).resolve() for arg in sys.argv[4:]]
    previous_output: str | None = None

    for total in range(STEP, PER_STREAM * len(bases) + 1, STEP):
        states = states_for_total(bases, total)
        missing = [str(path) for path in states if not path.is_file()]
        if missing:
            print(f"missing checkpoint for refinement_signatures={total}: {missing[0]}")
            return 3

        completed = subprocess.run(
            [str(binary), "--merge", *(str(path) for path in states)],
            check=True,
            text=True,
            capture_output=True,
        )
        lines = completed.stdout.splitlines()
        if not any(line.startswith(f"checkpoint={total} ") for line in lines):
            print(f"merged checkpoint count mismatch at {total}", file=sys.stderr)
            return 4
        accepted = SUCCESS in lines
        print(
            f"refinement_signatures={total} "
            f"public_forgery={'ACCEPT' if accepted else 'REJECT'}",
            flush=True,
        )
        if accepted:
            result_path.write_text(completed.stdout, encoding="utf-8")
            if previous_output is not None:
                previous_path.write_text(previous_output, encoding="utf-8")
            print(f"first_public_success={total}")
            return 0
        previous_output = completed.stdout

    print("public_ladder=NO_SOLUTION")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

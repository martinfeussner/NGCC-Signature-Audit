"""Collect refinement checkpoints and stop at the first public forgery."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scan_public_ladder import PER_STREAM, STEP, SUCCESS, states_for_total


def merge(binary: Path, states: list[Path], total: int) -> tuple[str, bool]:
    completed = subprocess.run(
        [str(binary), "--merge", *(str(path) for path in states)],
        check=True,
        text=True,
        capture_output=True,
    )
    lines = completed.stdout.splitlines()
    if not any(line.startswith(f"checkpoint={total} ") for line in lines):
        raise RuntimeError(f"merged checkpoint count mismatch at {total}")
    return completed.stdout, SUCCESS in lines


def record(
    outdir: Path,
    normal_log: list[str],
    poison_log: list[str],
    normal_output: str,
    poison_output: str,
    previous_normal: str | None,
    previous_poison: str | None,
    total: int,
) -> None:
    normal_log.append(f"first_public_success={total}")
    poison_log.append(f"first_public_success={total}")
    (outdir / "public_ladder.txt").write_text(
        "\n".join(normal_log) + "\n", encoding="utf-8"
    )
    (outdir / "public_ladder_poison.txt").write_text(
        "\n".join(poison_log) + "\n", encoding="utf-8"
    )
    (outdir / "cs128_public_ladder_result.txt").write_text(
        normal_output, encoding="utf-8"
    )
    (outdir / "cs128_public_ladder_poison_result.txt").write_text(
        poison_output, encoding="utf-8"
    )
    if previous_normal is not None and previous_poison is not None:
        (outdir / "cs128_public_ladder_previous.txt").write_text(
            previous_normal, encoding="utf-8"
        )
        (outdir / "cs128_public_ladder_poison_previous.txt").write_text(
            previous_poison, encoding="utf-8"
        )


def evaluate(
    normal_binary: Path,
    poison_binary: Path,
    states: list[Path],
    total: int,
    normal_log: list[str],
    poison_log: list[str],
) -> tuple[str, str, bool]:
    normal_output, normal_accept = merge(normal_binary, states, total)
    poison_output, poison_accept = merge(poison_binary, states, total)
    if normal_accept != poison_accept:
        raise RuntimeError(
            f"normal and poison public decisions differ at {total} signatures"
        )
    status = "ACCEPT" if normal_accept else "REJECT"
    normal_log.append(
        f"refinement_signatures={total} public_forgery={status}"
    )
    poison_log.append(
        f"refinement_signatures={total} public_forgery={status}"
    )
    print(normal_log[-1], flush=True)
    return normal_output, poison_output, normal_accept


def main() -> int:
    if len(sys.argv) < 8:
        print(
            "usage: collect_until_public_success.py NORMAL_BINARY POISON_BINARY "
            "COARSE_RAW OUTDIR TAIL_STATE_BASE WORKER_ID PRIOR_STATE_BASE "
            "[PRIOR_STATE_BASE ...]",
            file=sys.stderr,
        )
        return 2

    normal_binary = Path(sys.argv[1]).resolve()
    poison_binary = Path(sys.argv[2]).resolve()
    coarse_raw = Path(sys.argv[3]).resolve()
    outdir = Path(sys.argv[4]).resolve()
    tail_base = Path(sys.argv[5]).resolve()
    worker_id = int(sys.argv[6])
    prior_bases = [Path(arg).resolve() for arg in sys.argv[7:]]
    outdir.mkdir(parents=True, exist_ok=True)

    normal_log: list[str] = []
    poison_log: list[str] = []
    previous_normal: str | None = None
    previous_poison: str | None = None

    prior_total = PER_STREAM * len(prior_bases)
    for total in range(STEP, prior_total + 1, STEP):
        states = states_for_total(prior_bases, total)
        normal_output, poison_output, accepted = evaluate(
            normal_binary,
            poison_binary,
            states,
            total,
            normal_log,
            poison_log,
        )
        if accepted:
            record(
                outdir,
                normal_log,
                poison_log,
                normal_output,
                poison_output,
                previous_normal,
                previous_poison,
                total,
            )
            return 0
        previous_normal, previous_poison = normal_output, poison_output

    env = os.environ.copy()
    env["CS_PAUSE_AT_CHECKPOINT"] = "1"
    collector_log_path = outdir / "stage2b_worker_1.log"
    collector_err_path = outdir / "stage2b_worker_1.err"
    with collector_log_path.open("w", encoding="utf-8", buffering=1) as log, \
         collector_err_path.open("w", encoding="utf-8", buffering=1) as err:
        proc = subprocess.Popen(
            [
                str(normal_binary),
                str(PER_STREAM),
                str(STEP),
                str(worker_id),
                str(tail_base),
                str(coarse_raw),
            ],
            cwd=outdir,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=err,
            text=True,
            bufsize=1,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None

        for line in proc.stdout:
            log.write(line)
            print(line, end="", flush=True)
            if not line.startswith("checkpoint_state_ready="):
                continue
            tail_count = int(line.split("=", 1)[1])
            total = prior_total + tail_count
            tail_state = Path(f"{tail_base}.{tail_count}")
            normal_output, poison_output, accepted = evaluate(
                normal_binary,
                poison_binary,
                [*prior_bases, tail_state],
                total,
                normal_log,
                poison_log,
            )
            if accepted:
                record(
                    outdir,
                    normal_log,
                    poison_log,
                    normal_output,
                    poison_output,
                    previous_normal,
                    previous_poison,
                    total,
                )
                proc.stdin.close()
                code = proc.wait()
                if code != 8:
                    raise RuntimeError(
                        f"paused collector returned {code}, expected checkpoint EOF status 8"
                    )
                return 0
            previous_normal, previous_poison = normal_output, poison_output
            proc.stdin.write("\n")
            proc.stdin.flush()

        code = proc.wait()

    if code != 0:
        raise RuntimeError(f"collector returned {code}")

    # The final 500,000 checkpoint is stored at the unsuffixed base and does
    # not pause inside the C collector.
    total = prior_total + PER_STREAM
    normal_output, poison_output, accepted = evaluate(
        normal_binary,
        poison_binary,
        [*prior_bases, tail_base],
        total,
        normal_log,
        poison_log,
    )
    if accepted:
        record(
            outdir,
            normal_log,
            poison_log,
            normal_output,
            poison_output,
            previous_normal,
            previous_poison,
            total,
        )
        return 0

    normal_log.append("public_ladder=NO_SOLUTION")
    poison_log.append("public_ladder=NO_SOLUTION")
    (outdir / "public_ladder.txt").write_text(
        "\n".join(normal_log) + "\n", encoding="utf-8"
    )
    (outdir / "public_ladder_poison.txt").write_text(
        "\n".join(poison_log) + "\n", encoding="utf-8"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

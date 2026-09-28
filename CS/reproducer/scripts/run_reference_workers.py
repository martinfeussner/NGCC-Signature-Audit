import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 7:
        print(
            "usage: run_reference_workers.py COUNT WORKERS BINARY OUTDIR "
            "PREFIX WORKER_OFFSET [EXTRA ...]",
            file=sys.stderr,
        )
        return 2

    count = int(sys.argv[1])
    workers = int(sys.argv[2])
    binary = Path(sys.argv[3]).resolve()
    outdir = Path(sys.argv[4]).resolve()
    prefix = sys.argv[5]
    worker_offset = int(sys.argv[6])
    extra = [str(Path(arg).resolve()) for arg in sys.argv[7:]]
    outdir.mkdir(parents=True, exist_ok=True)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    checkpoint = min(count, 100_000)
    running = []

    for slot in range(1, workers + 1):
        worker_id = worker_offset + slot
        state = outdir / f"{prefix}_state_{slot}.bin"
        log = open(outdir / f"{prefix}_worker_{slot}.log", "w", buffering=1)
        err = open(outdir / f"{prefix}_worker_{slot}.err", "w", buffering=1)
        cmd = [
            str(binary),
            str(count),
            str(checkpoint),
            str(worker_id),
            str(state),
            *extra,
        ]
        proc = subprocess.Popen(
            cmd,
            cwd=outdir,
            stdout=log,
            stderr=err,
            creationflags=creationflags,
        )
        running.append((slot, worker_id, proc, log, err))
        print(f"slot={slot} worker_id={worker_id} pid={proc.pid}", flush=True)

    rc = 0
    for slot, worker_id, proc, log, err in running:
        code = proc.wait()
        log.close()
        err.close()
        print(f"slot={slot} worker_id={worker_id} exit={code}", flush=True)
        rc |= code
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

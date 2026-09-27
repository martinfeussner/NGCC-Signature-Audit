#!/usr/bin/env python3
"""Public-key-only structural inversion of submitted VDOO-128 keys.

The script attacks the actual public-key distribution produced by the NGCC
reference implementation.  It first recovers the hidden second oil space from
rank-one Jacobians, quotients it out, recovers the remaining triangular flag,
inverts the quotient map, and lifts the solution through the recovered O2
space.  Secret-key data is never supplied to an attack step.
"""

from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import time

import numpy as np

from vdoo_rankone_level1 import (
    D,
    M,
    M_BYTES,
    N,
    O1,
    O2,
    PK_BYTES,
    V,
    generate_submitted_key,
    unpack_nibbles,
)
from vdoo_rankone_toy import (
    MUL,
    derivative_matrix,
    gf_rank_rref,
    recover_rank_one_lines,
    recover_rank_one_lines_split5,
)
from vdoo_structural_core import (
    QuadraticMap,
    gf_matvec,
    gf_row_comb,
    layer_directions,
    normalize_subspace,
    ordered_forms_from_flag,
    recover_output_flag,
    recover_tail_flag,
    solve_linear,
    solve_triangular_map,
)


def parse_public_map(pk: bytes) -> QuadraticMap:
    if len(pk) != PK_BYTES:
        raise ValueError(f"wrong public-key length: {len(pk)}")
    polars = np.zeros((M, N, N), dtype=np.uint8)
    diags = np.zeros((M, N), dtype=np.uint8)
    monom = 0
    for i in range(N):
        for j in range(i, N):
            coeff = unpack_nibbles(pk[monom * M_BYTES : (monom + 1) * M_BYTES], M)
            if i == j:
                diags[:, i] = coeff
            else:
                polars[:, i, j] = coeff
                polars[:, j, i] = coeff
            monom += 1
    return QuadraticMap(polars, diags)


def hash_target(helper_path: Path, message: bytes, salt: bytes) -> np.ndarray:
    helper = ctypes.CDLL(str(helper_path))
    fn = helper.vdoo_hash_target
    fn.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    fn.restype = ctypes.c_int
    out = (ctypes.c_ubyte * M_BYTES)()
    msg = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    salt_buf = (ctypes.c_ubyte * 16).from_buffer_copy(salt)
    rc = fn(out, msg, len(message), salt_buf)
    if rc != 0:
        raise RuntimeError(f"VDOO target hash failed: {rc}")
    return unpack_nibbles(bytes(out), M)


def pack_nibbles(x: np.ndarray) -> bytes:
    out = bytearray((len(x) + 1) // 2)
    for i, value in enumerate(x):
        out[i // 2] |= int(value) << (4 * (i & 1))
    return bytes(out)


def submitted_verify(lib_path: Path, pk: bytes, message: bytes, signature: bytes) -> int:
    lib = ctypes.CDLL(str(lib_path))
    fn = lib.sig_verify
    fn.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulonglong,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulonglong,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulonglong,
    ]
    fn.restype = ctypes.c_int
    pk_buf = (ctypes.c_ubyte * len(pk)).from_buffer_copy(pk)
    sig_buf = (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
    msg_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    return int(fn(pk_buf, len(pk), sig_buf, len(signature), msg_buf, len(message)))


def output_line_of_rank_one(qmap: QuadraticMap, x: np.ndarray) -> np.ndarray:
    jac = derivative_matrix(qmap.polars, x)
    if gf_rank_rref(jac)[0] != 1:
        raise ValueError("derivative is not rank one")
    for j in range(qmap.n):
        if np.any(jac[:, j]):
            return jac[:, j].copy()
    raise ValueError("zero derivative")


def lift_through_subspace(
    qmap: QuadraticMap,
    x: np.ndarray,
    target: np.ndarray,
    kernel_basis: np.ndarray,
) -> np.ndarray | None:
    residual = target ^ qmap.evaluate(x)
    columns = []
    for o in kernel_basis:
        jac_o = derivative_matrix(qmap.polars, o)
        columns.append(gf_matvec(jac_o, x))
    linear = np.stack(columns, axis=1)
    coeff = solve_linear(linear, residual)
    if coeff is None:
        return None
    oil = gf_row_comb(coeff, kernel_basis)
    result = x ^ oil
    if not np.array_equal(qmap.evaluate(result), target):
        raise RuntimeError("O2 lift did not verify")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pk", type=Path, help="raw VDOO-128 public key")
    parser.add_argument("--seed", type=int, default=0x56444F4F2026)
    parser.add_argument("--max-lifts", type=int, default=2000)
    parser.add_argument("--fresh", action="store_true", help="discard cached attack state")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "forgery_evidence",
        help="directory for the public key, message, signature, and verdict",
    )
    parser.add_argument(
        "--message",
        default="Public-key-only structural forgery against submitted VDOO-128",
    )
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    here = Path(__file__).resolve().parent
    lib_path = here.parent / "ngcc-harness/sign-33/lib/libvdoo_128.so"
    state_path = here / "vdoo128_attack_state.npz"
    state = None
    if state_path.exists() and not args.fresh and not args.pk:
        state = np.load(state_path)
        pk = bytes(state["pk"].tolist())
        print(f"loaded cached public-only attack state (stage {int(state['stage'])})", flush=True)
    elif args.pk:
        pk = args.pk.read_bytes()
    else:
        pk, _validation_sk = generate_submitted_key(lib_path)

    attack_start = time.perf_counter()
    qmap = parse_public_map(pk)
    print(f"loaded public map F16^{N} -> F16^{M}", flush=True)

    if state is not None and int(state["stage"]) >= 1:
        o2_basis = state["o2_basis"]
        q2_basis = state["q2_basis"]
    else:
        t0 = time.perf_counter()
        o2_lines = recover_rank_one_lines(qmap.polars, rng, trials=1)
        o2_basis = normalize_subspace(np.stack(o2_lines))
        if len(o2_basis) != O2:
            raise RuntimeError(f"recovered O2 dimension {len(o2_basis)}, expected {O2}")
        if any(np.any(qmap.evaluate(o)) for o in o2_basis):
            raise RuntimeError("recovered O2 is not a public zero subspace")
        q2_basis = normalize_subspace(
            np.stack([output_line_of_rank_one(qmap, o) for o in o2_lines])
        )
        if len(q2_basis) != O2:
            raise RuntimeError(f"recovered Q2 dimension {len(q2_basis)}, expected {O2}")
        print(f"recovered O2 and Q2 in {time.perf_counter() - t0:.2f}s", flush=True)
        if not args.pk:
            np.savez_compressed(
                state_path,
                stage=np.array(1),
                pk=np.frombuffer(pk, dtype=np.uint8),
                o2_basis=o2_basis,
                q2_basis=q2_basis,
            )

    t0 = time.perf_counter()
    quotient, representatives, projection = qmap.quotient(o2_basis, q2_basis)
    if (quotient.n, quotient.m) != (V + D + O1, D + O1):
        raise RuntimeError("unexpected quotient dimensions")
    print(
        f"constructed quotient F16^{quotient.n} -> F16^{quotient.m} "
        f"in {time.perf_counter() - t0:.2f}s",
        flush=True,
    )

    if state is not None and int(state["stage"]) >= 2:
        o1_basis = state["o1_basis"]
        q1_basis = state["q1_basis"]
    else:
        t0 = time.perf_counter()
        total_labels = 273 * 256
        print(
            f"recovering the {O1} quotient O1 lines from {total_labels} "
            f"projective multipencil labels",
            flush=True,
        )
        o1_lines = recover_rank_one_lines_split5(
            quotient.polars,
            rng,
            progress_every=1000,
        )
        o1_basis = normalize_subspace(np.stack(o1_lines))
        if len(o1_basis) != O1:
            raise RuntimeError(f"recovered quotient O1 dimension {len(o1_basis)}, expected {O1}")
        if any(np.any(quotient.evaluate(o)) for o in o1_basis):
            raise RuntimeError("recovered quotient O1 is not a public zero subspace")
        q1_basis = normalize_subspace(
            np.stack([output_line_of_rank_one(quotient, o) for o in o1_lines])
        )
        if len(q1_basis) != O1:
            raise RuntimeError(f"recovered quotient Q1 dimension {len(q1_basis)}, expected {O1}")
        print(f"recovered quotient O1 and Q1 in {time.perf_counter() - t0:.2f}s", flush=True)
        if not args.pk:
            np.savez_compressed(
                state_path,
                stage=np.array(2),
                pk=np.frombuffer(pk, dtype=np.uint8),
                o2_basis=o2_basis,
                q2_basis=q2_basis,
                o1_basis=o1_basis,
                q1_basis=q1_basis,
            )

    t0 = time.perf_counter()
    diagonal, representatives1, projection1 = quotient.quotient(o1_basis, q1_basis)
    if (diagonal.n, diagonal.m) != (V + D, D):
        raise RuntimeError("unexpected diagonal quotient dimensions")
    print(
        f"constructed diagonal quotient F16^{diagonal.n} -> F16^{diagonal.m} "
        f"in {time.perf_counter() - t0:.2f}s",
        flush=True,
    )

    if state is not None and int(state["stage"]) >= 3:
        output_transform = state["output_transform"]
        rank_tests = 0
        print("loaded cached diagonal flag", flush=True)
    else:
        t0 = time.perf_counter()
        flags, rank_tests = recover_output_flag(diagonal, V, rng, verbose=True)
        output_transform = ordered_forms_from_flag(flags)
        print(
            f"recovered diagonal output flag in {time.perf_counter() - t0:.2f}s "
            f"({rank_tests} rank tests)",
            flush=True,
        )
        if not args.pk:
            np.savez_compressed(
                state_path,
                stage=np.array(3),
                pk=np.frombuffer(pk, dtype=np.uint8),
                o2_basis=o2_basis,
                q2_basis=q2_basis,
                o1_basis=o1_basis,
                q1_basis=q1_basis,
                output_transform=output_transform,
            )

    t0 = time.perf_counter()
    ordered = diagonal.output_transform(output_transform)
    tails = recover_tail_flag(ordered)
    expected_dims = [diagonal.m - l for l in range(1, diagonal.m + 1)]
    actual_dims = [len(tails[l]) for l in range(1, diagonal.m + 1)]
    if actual_dims != expected_dims:
        raise RuntimeError(
            f"recovered tail dimensions are wrong: {actual_dims} != {expected_dims}"
        )
    directions = layer_directions(tails, V)
    print(
        f"verified the 16-layer diagonal and input-tail flags in "
        f"{time.perf_counter() - t0:.2f}s",
        flush=True,
    )

    message = args.message.encode("utf-8")
    salt = bytes(rng.integers(0, 256, size=16, dtype=np.uint8).tolist())
    helper_path = here / "libvdoo_hash_helper.so"
    if not helper_path.exists():
        raise RuntimeError("build the hash helper with `make -C VDOO_structural_attack`")
    target = hash_target(helper_path, message, salt)
    quotient_target = gf_matvec(projection, target)
    diagonal_target = gf_matvec(projection1, quotient_target)
    ordered_target = gf_matvec(output_transform, diagonal_target)

    t0 = time.perf_counter()
    solution = None
    quotient_attempts = 0
    for lift_attempt in range(1, args.max_lifts + 1):
        z2, used = solve_triangular_map(
            ordered, ordered_target, tails, directions, rng, max_attempts=10000
        )
        quotient_attempts += used
        z1 = gf_matvec(representatives1, z2)
        lifted1 = lift_through_subspace(quotient, z1, quotient_target, o1_basis)
        if lifted1 is None:
            continue
        x = gf_matvec(representatives, lifted1)
        residual = target ^ qmap.evaluate(x)
        if np.any(gf_matvec(projection, residual)):
            raise RuntimeError("quotient inversion did not land in Q2")
        solution = lift_through_subspace(qmap, x, target, o2_basis)
        if solution is not None:
            break
    if solution is None:
        raise RuntimeError("could not lift a quotient solution through O2")
    solve_time = time.perf_counter() - t0

    assert np.array_equal(qmap.evaluate(solution), target)
    signature = pack_nibbles(solution) + salt
    if len(signature) != 85:
        raise RuntimeError(f"wrong signature length {len(signature)}")
    verify_rc = submitted_verify(lib_path, pk, message, signature)
    if verify_rc != 0:
        raise RuntimeError(f"submitted verifier rejected the forgery: {verify_rc}")

    evidence = args.evidence_dir
    evidence.mkdir(exist_ok=True)
    (evidence / "public_key.bin").write_bytes(pk)
    (evidence / "message.bin").write_bytes(message)
    (evidence / "signature.bin").write_bytes(signature)
    (evidence / "verification.txt").write_text(
        "VDOO-128 submitted verifier return code: 0 (accepted)\n",
        encoding="utf-8",
    )
    print(
        f"forged the fresh message in {solve_time:.2f}s; "
        f"quotient attempts={quotient_attempts}, O2 lift attempts={lift_attempt}",
        flush=True,
    )
    print(
        f"SUBMITTED VERIFIER ACCEPTED THE PUBLIC-KEY-ONLY FORGERY in "
        f"{time.perf_counter() - attack_start:.2f}s",
        flush=True,
    )


if __name__ == "__main__":
    main()

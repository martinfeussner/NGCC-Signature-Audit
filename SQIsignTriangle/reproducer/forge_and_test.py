#!/usr/bin/env python3
import argparse
import ctypes as C
import hashlib
import subprocess
import tempfile
import time
from pathlib import Path

U8 = C.c_ubyte
ULL = C.c_ulonglong
PTR = C.POINTER(U8)


def array(data):
    return (U8 * len(data)).from_buffer_copy(data)


def load_library(path):
    lib = C.CDLL(str(path))
    lib.ngcc_seed.argtypes = [PTR, ULL]
    lib.ngcc_seed.restype = C.c_int
    for name in ("sig_get_pk_len_bytes", "sig_get_sk_len_bytes", "sig_get_sn_len_bytes"):
        getattr(lib, name).restype = ULL
    lib.sig_keygen.argtypes = [PTR, C.POINTER(ULL), PTR, C.POINTER(ULL)]
    lib.sig_keygen.restype = C.c_int
    lib.sig_sign.argtypes = [PTR, ULL, PTR, ULL, PTR, C.POINTER(ULL)]
    lib.sig_sign.restype = C.c_int
    lib.sig_verify.argtypes = [PTR, ULL, PTR, ULL, PTR, ULL]
    lib.sig_verify.restype = C.c_int
    return lib


def verify(lib, public_key, signature, message):
    return lib.sig_verify(
        array(public_key), len(public_key), array(signature), len(signature),
        array(message), len(message)
    )


def forge(helper, public_key, signature, target, directory):
    paths = []
    for name, data in (("pk", public_key), ("sig", signature), ("target", target)):
        path = directory / f"{name}.bin"
        path.write_bytes(data)
        paths.append(path)
    output = subprocess.check_output([str(helper), *map(str, paths)], text=True)
    values = {
        key: int(value)
        for key, value in (line.split("=", 1) for line in output.splitlines())
    }
    e, q = values["e"], values["q"]
    modulus = 1 << e
    lower = 1 << (e - 1)
    selected = None
    for factor in (1, 2):
        c1 = values[f"target{factor}_c1"]
        c2 = values[f"target{factor}_c2"]
        if lower <= 2 * c1:
            continue
        k = (lower - c2 + c1 - 1) // c1
        q_prime = c2 + k * c1
        if not q_prime & 1:
            q_prime += c1
        if lower <= q_prime < modulus and q_prime & 1:
            selected = factor, c1, c2, q_prime
            break
    if selected is None:
        raise RuntimeError(
            "neither target branch meets the public response-size condition"
        )
    factor, c1, c2, q_prime = selected
    assert (q_prime - c2) % c1 == 0
    u = q_prime * pow(q, -1, modulus) % modulus

    forged = bytearray(signature)
    fp2_bytes = len(public_key) - 1
    coefficient_bytes = (len(signature) - fp2_bytes) // 5
    assert fp2_bytes + 5 * coefficient_bytes == len(signature)
    for index in range(4):
        offset = fp2_bytes + index * coefficient_bytes
        coefficient = int.from_bytes(
            forged[offset:offset + coefficient_bytes], "little"
        ) % modulus
        transformed = coefficient * u % modulus
        forged[offset:offset + coefficient_bytes] = transformed.to_bytes(
            coefficient_bytes, "little"
        )
    forged[-coefficient_bytes:] = q_prime.to_bytes(coefficient_bytes, "little")
    return bytes(forged), e, factor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--level", type=int, choices=(1, 2, 5, 6), required=True)
    parser.add_argument("--keys", type=int, default=3)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    library_path = (
        args.harness.resolve() / "sign-27/lib" /
        f"libSQIsignTriangle_lvl{args.level}.so"
    )
    helper = root / "build" / f"recover_codomain_lvl{args.level}"
    if not helper.exists():
        raise SystemExit(f"missing {helper}; run make LEVEL={args.level} first")
    lib = load_library(library_path)
    pk_bytes = int(lib.sig_get_pk_len_bytes())
    sk_bytes = int(lib.sig_get_sk_len_bytes())
    sig_bytes = int(lib.sig_get_sn_len_bytes())

    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        for index in range(args.keys):
            seed = hashlib.shake_256(
                f"SQIsignTriangle level {args.level}, key {index}".encode()
            ).digest(48)
            assert lib.ngcc_seed(array(seed), len(seed)) == 0
            pk_buffer, sk_buffer = (U8 * pk_bytes)(), (U8 * sk_bytes)()
            pk_length, sk_length = ULL(), ULL()
            assert lib.sig_keygen(
                pk_buffer, C.byref(pk_length), sk_buffer, C.byref(sk_length)
            ) == 0
            assert pk_length.value == pk_bytes and sk_length.value == sk_bytes
            public_key, secret_key = bytes(pk_buffer), bytes(sk_buffer)
            source = f"SQIsignTriangle source, level {args.level}, key {index}".encode()
            target = f"SQIsignTriangle fresh target, level {args.level}, key {index}".encode()
            sig_buffer, sig_length = (U8 * sig_bytes)(), ULL()
            assert lib.sig_sign(
                array(secret_key), len(secret_key), array(source), len(source),
                sig_buffer, C.byref(sig_length)
            ) == 0
            assert sig_length.value == sig_bytes
            signature = bytes(sig_buffer)
            del secret_key, sk_buffer
            assert verify(lib, public_key, signature, source) == 0
            assert verify(lib, public_key, signature, target) != 0
            started = time.perf_counter()
            forged, e, factor = forge(
                helper, public_key, signature, target, directory
            )
            elapsed = time.perf_counter() - started
            assert verify(lib, public_key, forged, target) == 0
            assert verify(lib, public_key, forged, source) != 0
            print(
                f"level={args.level} key={index} e={e} factor={factor} "
                f"forge={elapsed:.3f}s ACCEPT",
                flush=True,
            )


if __name__ == "__main__":
    main()

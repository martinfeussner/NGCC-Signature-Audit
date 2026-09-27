#!/usr/bin/env python3
"""Verify the saved VDOO-128 forgery with the submitted verifier."""

from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path


HERE = Path(__file__).resolve().parent
ATTACK = HERE / "VDOO_structural_attack"
EVIDENCE = ATTACK / "forgery_evidence"

EXPECTED = {
    "public_key.bin": "f0bf3e7faaa200c14c8b37c12d4a0d7195d2ff6c0ce8081e29ea303a4b3d91c6",
    "message.bin": "31b942f4df86978090308e2bc13a54379dd0333c66d5210831d4ddf49ceeb575",
    "signature.bin": "575c13a9f988e6210c562c2cab861dc13228878c1aa45d7d7357f6188ea5b08c",
}


def c_buffer(value: bytes):
    return (ctypes.c_ubyte * len(value)).from_buffer_copy(value)


def main() -> None:
    values: dict[str, bytes] = {}
    for name, expected in EXPECTED.items():
        value = (EVIDENCE / name).read_bytes()
        digest = hashlib.sha256(value).hexdigest()
        if digest != expected:
            raise RuntimeError(f"{name}: SHA-256 {digest} != {expected}")
        values[name] = value

    library = ctypes.CDLL(str(HERE / "ngcc-harness/sign-33/lib/libvdoo_128.so"))
    verify = library.sig_verify
    verify.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong,
    ]
    verify.restype = ctypes.c_int

    pk = values["public_key.bin"]
    message = values["message.bin"]
    signature = values["signature.bin"]
    accepted = verify(
        c_buffer(pk), len(pk), c_buffer(signature), len(signature),
        c_buffer(message), len(message),
    )
    changed_message = bytes([message[0] ^ 1]) + message[1:]
    changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
    message_control = verify(
        c_buffer(pk), len(pk), c_buffer(signature), len(signature),
        c_buffer(changed_message), len(changed_message),
    )
    signature_control = verify(
        c_buffer(pk), len(pk), c_buffer(changed_signature), len(changed_signature),
        c_buffer(message), len(message),
    )
    print(
        f"forgery={accepted} changed-message={message_control} "
        f"changed-signature={signature_control}"
    )
    if accepted != 0 or message_control == 0 or signature_control == 0:
        raise SystemExit(1)
    print("VDOO evidence replay: PASS")


if __name__ == "__main__":
    main()

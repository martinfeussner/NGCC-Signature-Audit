#!/usr/bin/env python3
"""Align the submitted Qing Luan reference copies to PDF sections 1.8--1.10."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent / "spec-aligned"

OLD_LEAVES = """    {   /* SeedLeaves: t independent round seeds from (master_seed | Salt) */
        xof_ctx_t xof;
        xof_init(&xof);
        uint8_t d = DOMAIN_SEEDLEAVES;
        xof_absorb(&xof, &d, 1);
        xof_absorb(&xof, master_seed, PARAM_SEED_BYTES);
        xof_absorb(&xof, salt, PARAM_SALT_BYTES);
        xof_finalize(&xof);
        xof_squeeze(&xof, seed_leaves, (size_t)PARAM_TAU * PARAM_SEED_BYTES);
        secure_zero(&xof, sizeof(xof));
    }
"""

NEW_LEAVES = """    {   /* PDF 1.10: independent Seed[i] with one-based LE16(i). */
        for (int i = 0; i < PARAM_TAU; i++) {
            xof_ctx_t xof;
            uint8_t d = DOMAIN_SEEDLEAVES;
            uint16_t round = (uint16_t)(i + 1);
            uint8_t ib[2] = { (uint8_t)round, (uint8_t)(round >> 8) };
            xof_init(&xof);
            xof_absorb(&xof, &d, 1);
            xof_absorb(&xof, master_seed, PARAM_SEED_BYTES);
            xof_absorb(&xof, salt, PARAM_SALT_BYTES);
            xof_absorb(&xof, ib, sizeof(ib));
            xof_finalize(&xof);
            xof_squeeze(&xof,
                        seed_leaves + (size_t)i * PARAM_SEED_BYTES,
                        PARAM_SEED_BYTES);
            secure_zero(&xof, sizeof(xof));
        }
    }
"""

for profile in ("128", "256", "384", "512"):
    sign = ROOT / f"QingLuan-{profile}" / "src" / "sign.c"
    text = sign.read_text()
    if text.count(OLD_LEAVES) != 1:
        raise SystemExit(f"unexpected SeedLeaves block in {sign}")
    text = text.replace(OLD_LEAVES, NEW_LEAVES)
    if text.count("(uint16_t)(i + PARAM_C)") != 2:
        raise SystemExit(f"unexpected signer domain count in {sign}")
    text = text.replace("(uint16_t)(i + PARAM_C)",
                        "(uint16_t)(i + 1 + PARAM_C)")
    sign.write_text(text)

    verify = ROOT / f"QingLuan-{profile}" / "src" / "verify.c"
    text = verify.read_text()
    if text.count("(uint16_t)(i + PARAM_C)") != 1:
        raise SystemExit(f"unexpected verifier domain count in {verify}")
    text = text.replace("(uint16_t)(i + PARAM_C)",
                        "(uint16_t)(i + 1 + PARAM_C)")
    verify.write_text(text)


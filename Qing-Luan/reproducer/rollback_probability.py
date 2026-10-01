#!/usr/bin/env python3
"""Idealized failure probabilities for the combined rollback extractor.

This is an explanatory layered random-oracle model.  It is not an exact
probability statement about conditioned serialized signatures or the finite
digest-to-fixed-weight implementation.
"""

from decimal import Decimal, getcontext
from math import comb

getcontext().prec = 220
LN2 = Decimal(2).ln()

PARAMS = (
    (128, 256, 212),
    (256, 512, 424),
    (384, 763, 631),
    (512, 1018, 842),
)


def neg_log2(x: Decimal) -> Decimal:
    return -(x.ln() / LN2)


print(
    "level a cross_fixed_weight combined_digest_free "
    "layered_cross layered_combined"
)
for level, t, w in PARAMS:
    h = 2 * level
    a = t - w
    q = Decimal(2) ** Decimal(-h)
    D = Decimal(comb(t, w))

    cross_fixed = Decimal(1) / D
    combined_digest_free = cross_fixed / (Decimal(126) ** a)

    # A message-digest collision, or otherwise a challenge-1-digest collision,
    # repeats the complete remaining cascade.
    d = q + (Decimal(1) - q) * q
    # Conditional on distinct challenge-1 digests, model a challenge-2-digest
    # collision first and an otherwise uniform fixed-weight output second.
    c = q + (Decimal(1) - q) / D
    layered_cross = d + (Decimal(1) - d) * c
    layered_combined = d + (Decimal(1) - d) * c / (Decimal(126) ** a)

    print(
        level,
        a,
        f"{neg_log2(cross_fixed):.15f}",
        f"{neg_log2(combined_digest_free):.15f}",
        f"{neg_log2(layered_cross):.15f}",
        f"{neg_log2(layered_combined):.15f}",
    )

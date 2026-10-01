#!/usr/bin/env python3
"""Exact ideal-model success probability for two rollback transcripts."""

from decimal import Decimal, getcontext
from fractions import Fraction
from math import comb, log2

getcontext().prec = 80

PARAMETERS = {
    "QingLuan-128": (256, 212),
    "QingLuan-256": (512, 424),
    "QingLuan-384": (763, 631),
    "QingLuan-512": (1018, 842),
}

print("profile,t,w,type0,E_overlap,failure,success,log2_failure")
for name, (t, w) in PARAMETERS.items():
    a = t - w
    denominator = comb(t, a)
    lo = max(0, 2 * a - t)
    failure = Fraction(0, 1)
    for h in range(lo, a + 1):
        intersection_probability = Fraction(
            comb(a, h) * comb(t - a, a - h), denominator
        )
        failure += intersection_probability * Fraction(1, 126**h)
    fd = Decimal(failure.numerator) / Decimal(failure.denominator)
    success = Decimal(1) - fd
    expected = Decimal(a * a) / Decimal(t)
    print(
        f"{name},{t},{w},{a},{expected:.15f},{fd:.25E},"
        f"{success:.25f},{log2(float(fd)):.15f}"
    )


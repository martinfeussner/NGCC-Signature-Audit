#!/usr/bin/env python3
"""Recompute the Rhyme-128 cumulative envelope under both Gaussian readings."""

import math


R = 13
B1 = 388
SIGMA_Y = 122.0
SIGMA_BASE = 1.295870
SOURCE_M = 1155474732460784121 / 2**60


def audit(name, rho_y, rho_v):
    rows = []
    for parity in (0, 1):
        values = list(range(-12, 13, 2)) if parity == 0 else list(range(-13, 14, 2))
        normalizer = sum(rho_v(v) for v in values)
        probabilities = {v: rho_v(v) / normalizer for v in values}

        boundary_v = max(values)
        boundary = probabilities[boundary_v] * rho_y(B1) / rho_y(B1 + boundary_v)

        masses = []
        for y in range(-B1 - R, B1 + R + 1):
            mass = sum(
                probabilities[v] * rho_y(y + v) / rho_y(y)
                for v in values
                if abs(y + v) <= B1
            )
            masses.append((y, mass))
        required = max(mass for _, mass in masses)
        maximizers = [y for y, mass in masses if math.isclose(mass, required, abs_tol=1e-13)]
        rows.append((parity, boundary, required, maximizers))

    print(name)
    for parity, boundary, required, maximizers in rows:
        print(
            f"  c={parity}: M_boundary={boundary:.15g} "
            f"M_required={required:.15g} argmax={maximizers}"
        )
    return rows


def main():
    sigma_target_operational = 2 * SIGMA_BASE
    operational = audit(
        "operational CDT/source convention",
        lambda x: math.exp(-(x * x) / (2 * SIGMA_Y * SIGMA_Y)),
        lambda v: math.exp(-(v * v) / (2 * sigma_target_operational**2)),
    )

    sigma_target_literal = 4 * math.sqrt(math.pi) * SIGMA_BASE
    literal = audit(
        "literal PDF convention",
        lambda x: math.exp(-math.pi * x * x / (SIGMA_Y * SIGMA_Y)),
        lambda v: math.exp(-math.pi * v * v / (sigma_target_literal**2)),
    )

    expected = {
        "operational": (
            (9.35733971887221e-6, 1.00193648690613, [-378, 378]),
            (1.49503742309832e-6, 1.00192927708401, [-377, 377]),
        ),
        "literal": (
            (0.007537142284273044, 1.1818109123445615, [-380, 380]),
            (0.003519198100672961, 1.1821799192044165, [-379, 379]),
        ),
    }
    for actual, wanted in zip(operational, expected["operational"]):
        _, boundary, required, maximizers = actual
        assert math.isclose(boundary, wanted[0], rel_tol=1e-12)
        assert math.isclose(required, wanted[1], rel_tol=1e-12)
        assert maximizers == wanted[2]
    for actual, wanted in zip(literal, expected["literal"]):
        _, boundary, required, maximizers = actual
        assert math.isclose(boundary, wanted[0], rel_tol=1e-12)
        assert math.isclose(required, wanted[1], rel_tol=1e-12)
        assert maximizers == wanted[2]

    assert SOURCE_M > max(row[2] for row in operational)
    assert SOURCE_M < min(row[2] for row in literal)
    print(f"source M={SOURCE_M:.15g}")
    print("envelope audit: PASS")


if __name__ == "__main__":
    main()

"""Check the Gram-form implementation of the 64 posterior residual scores."""

import math
import random


def explicit_scores(z, products):
    scores = []
    for mask in range(64):
        signs = [1 if (mask >> g) & 1 else -1 for g in range(6)]
        total = 0.0
        for u, zv in enumerate(z):
            residual = zv + sum(signs[g] * products[g][u] for g in range(6))
            total += residual * residual
        scores.append(total)
    return scores


def gram_scores(z, products):
    zz = sum(v * v for v in z)
    zp = [sum(z[u] * products[g][u] for u in range(len(z))) for g in range(6)]
    pp = [[0.0] * 6 for _ in range(6)]
    for g in range(6):
        for h in range(g + 1):
            pp[g][h] = sum(
                products[g][u] * products[h][u] for u in range(len(z))
            )
    scores = []
    for mask in range(64):
        signs = [1 if (mask >> g) & 1 else -1 for g in range(6)]
        total = zz
        for g in range(6):
            total += 2.0 * signs[g] * zp[g] + pp[g][g]
            for h in range(g):
                total += 2.0 * signs[g] * signs[h] * pp[g][h]
        scores.append(total)
    return scores


def main():
    rng = random.Random(0x4353313238)
    worst = 0.0
    for _ in range(32):
        z = [rng.randint(-3000, 3000) for _ in range(768)]
        products = [
            [rng.randint(-300, 300) for _ in range(768)] for _ in range(6)
        ]
        direct = explicit_scores(z, products)
        gram = gram_scores(z, products)
        for a, b in zip(direct, gram):
            worst = max(worst, abs(a - b))
            if not math.isclose(a, b, rel_tol=1e-13, abs_tol=1e-7):
                raise AssertionError((a, b))
    print(f"posterior_quadratic_equivalence=PASS worst_abs_diff={worst:.1f}")


if __name__ == "__main__":
    main()

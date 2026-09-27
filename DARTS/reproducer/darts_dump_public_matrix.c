/* Dump the two public DARTS-128 ring-matrix polynomials used by completion.
 * The input is a public score blob; no secret data is read. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "darts_scores.h"
#include "packing.h"
#include "poly.h"
#include "polymat.h"
#include "reduce.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s public-score\n", argv[0]);
    return 2;
  }
  darts_score_blob score;
  FILE *fp = fopen(argv[1], "rb");
  if (!fp || fread(&score, sizeof score, 1, fp) != 1 || fclose(fp) != 0 ||
      memcmp(score.magic, DARTS_SCORE_MAGIC, sizeof score.magic) != 0 ||
      score.n != N || score.secret_polys != DARTS_SECRET_POLYS)
    return 2;

  uint8_t seed_a[SEEDBYTES];
  polyveck a0;
  polyvecl a[K];
  unpack_pk(&a0, seed_a, score.public_key);
  polymatkl_expand(a, seed_a);
  a[0].vec[0] = a0.vec[0];
  for (unsigned p = 0; p < L; ++p) {
    poly standard = a[0].vec[p];
    poly_invntt_tomont(&standard);
    for (unsigned i = 0; i < N; ++i)
      /* invntt_tomont leaves a Montgomery factor. */
      printf("%u %u %d\n", p, i, freeze_centered(
             montgomery_reduce(standard.coeffs[i])));
  }
  return 0;
}

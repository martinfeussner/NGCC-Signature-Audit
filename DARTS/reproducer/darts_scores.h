#ifndef DARTS_SCORES_H
#define DARTS_SCORES_H

#include <stdint.h>
#include "params.h"

#define DARTS_SCORE_MAGIC "DARTS02"
/* Only s0,s1 need statistical recovery.  The public-key equation then derives
 * e1 exactly and tests that all of its coefficients are ternary. */
#define DARTS_SECRET_POLYS L

typedef struct {
  char magic[8];
  uint32_t n;
  uint32_t secret_polys;
  uint64_t signatures;
  uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
  double theta[DARTS_SECRET_POLYS][N];
} darts_score_blob;

#define DARTS_STATE_MAGIC "DARTST2"

typedef struct {
  char magic[8];
  uint32_t n;
  uint32_t secret_polys;
  uint64_t signatures;
  uint64_t attempts;
  uint64_t branch0;
  uint64_t branch1;
  uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
  int64_t acc[DARTS_SECRET_POLYS][N];
  int64_t gram[N];
} darts_accumulator_state;

#endif

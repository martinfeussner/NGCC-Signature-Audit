/* Produce and verify a fresh DARTS-128 signature from an equivalent ternary
 * secret recovered by a public completion stage. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "darts_scores.h"
#include "drng.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"

extern DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s score-file ternary-secret signature-output\n",
            argv[0]);
    return 2;
  }
  darts_score_blob blob;
  FILE *fp = fopen(argv[1], "rb");
  if (!fp || fread(&blob, sizeof blob, 1, fp) != 1 || fclose(fp) != 0 ||
      memcmp(blob.magic, DARTS_SCORE_MAGIC, sizeof blob.magic) != 0 ||
      blob.n != N || blob.secret_polys != DARTS_SECRET_POLYS)
    return 2;

  poly s0;
  polyvecl_1 s1;
  polyveck e;
  fp = fopen(argv[2], "r");
  if (!fp) return 2;
  for (unsigned p = 0; p < L + K; ++p)
    for (unsigned i = 0; i < N; ++i) {
      int value;
      if (fscanf(fp, "%d", &value) != 1 || value < -1 || value > 1)
        return 2;
      if (p == 0) s0.coeffs[i] = value;
      else if (p < L) s1.vec[p - 1].coeffs[i] = value;
      else e.vec[p - L].coeffs[i] = value;
    }
  int extra;
  if (fscanf(fp, "%d", &extra) != EOF || fclose(fp) != 0) return 2;

  uint8_t sk[CRYPTO_SECRETKEYBYTES], sig[CRYPTO_SIGNATUREBYTES];
  uint8_t key[SEEDBYTES], seed[48];
  memset(key, 0xA7, sizeof key);
  for (unsigned i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)(0x91 + 3*i);
  pack_sk(sk, blob.public_key, &s0, &s1, &e, key);
  if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) return 2;
  static const uint8_t message[] =
      "fresh DARTS message signed with the lattice-recovered equivalent key";
  size_t siglen = 0;
  int src = crypto_sign_signature(sig, &siglen, message, sizeof message - 1, sk);
  int accepted = src == 0 && siglen == CRYPTO_SIGNATUREBYTES &&
      crypto_sign_verify(sig, siglen, message, sizeof message - 1,
                         blob.public_key) == 0;
  uint8_t changed[sizeof message];
  memcpy(changed, message, sizeof message);
  changed[0] ^= 1;
  int changed_accepted = src == 0 && siglen == CRYPTO_SIGNATUREBYTES &&
      crypto_sign_verify(sig, siglen, changed, sizeof message - 1,
                         blob.public_key) == 0;
  if (!accepted || changed_accepted) {
    printf("fresh_message_forgery=%s changed_message=%s\n",
           accepted ? "ACCEPTED" : "REJECTED",
           changed_accepted ? "ACCEPTED" : "REJECTED");
    return 1;
  }
  fp = fopen(argv[3], "wb");
  if (!fp || fwrite(sig, siglen, 1, fp) != 1 || fclose(fp) != 0) return 2;
  printf("fresh_message_forgery=ACCEPTED changed_message=REJECTED "
         "bytes=%zu signature=%s\n", siglen, argv[3]);
  return 0;
}

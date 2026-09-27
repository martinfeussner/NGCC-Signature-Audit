/* Export the public full-t Module-LWR instance after public t0 recovery. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

typedef struct {
  char magic[8];
  uint32_t n, k, kappa, public_key_bytes;
  uint64_t signatures;
  unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
} hint_header;

typedef struct {
  char magic[8];
  uint32_t n, k, l, q, p;
} lwr_header;

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s hint_observations recovered_t0.txt output.bin\n", argv[0]);
    return 64;
  }
  FILE *hf = fopen(argv[1], "rb");
  hint_header hh;
  if (!hf || fread(&hh, sizeof hh, 1, hf) != 1 || fclose(hf) != 0 ||
      memcmp(hh.magic, "ATLHNT1", 8) != 0 || hh.n != N || hh.k != K ||
      hh.public_key_bytes != CRYPTO_PUBLICKEYBYTES) {
    fputs("invalid hint observation file\n", stderr);
    return 2;
  }

  polyveck t0;
  FILE *tf = fopen(argv[2], "r");
  if (!tf) return 3;
  for (unsigned i = 0; i < K; ++i)
    for (unsigned j = 0; j < N; ++j) {
      int value;
      if (fscanf(tf, "%d", &value) != 1 || value < -511 || value > 512)
        return 4;
      t0.vec[i].coeffs[j] = (uint32_t)(value + (int)P) & (P - 1);
    }
  if (fclose(tf) != 0) return 5;

  unsigned char rho[SEEDBYTES];
  polyveck t1, t;
  polyvecl mat[K];
  unpack_pk(rho, &t1, hh.public_key);
  expand_mat(mat, rho);
  for (unsigned i = 0; i < K; ++i)
    for (unsigned j = 0; j < N; ++j)
      t.vec[i].coeffs[j] = ((t1.vec[i].coeffs[j] << D) +
                            t0.vec[i].coeffs[j]) & (P - 1);

  FILE *out = fopen(argv[3], "wb");
  if (!out) return 6;
  lwr_header header = {{0}, N, K, L, Q, P};
  memcpy(header.magic, "ATLLWR1", 8);
  if (fwrite(&header, sizeof header, 1, out) != 1 ||
      fwrite(mat, sizeof mat, 1, out) != 1 ||
      fwrite(&t, sizeof t, 1, out) != 1 || fclose(out) != 0)
    return 7;
  printf("exported n=%u k=%u l=%u q=%u p=%u signatures=%llu output=%s\n",
         N, K, L, Q, P, (unsigned long long)hh.signatures, argv[3]);
  return 0;
}

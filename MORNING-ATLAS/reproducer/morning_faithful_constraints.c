/* Collect exact public support inequalities for faithful MORNING-ATLAS-128.
 * Each row follows from y=z-c*s1 and the specified sampler support
 * |y_j| <= gamma1-1.  The output contains only the public key and inequalities;
 * a separate optional calibration file contains the true s1. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

typedef struct {
  char magic[8];
  uint32_t n, l, kappa, public_key_bytes;
  uint64_t signatures, constraints;
  unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
} constraint_header;

typedef struct {
  uint8_t polynomial;
  int8_t sense; /* +1: row*s >= bound; -1: row*s <= bound */
  int16_t bound;
  int8_t row[N];
} constraint_row;

static inline int32_t centered(uint32_t x) {
  x &= Q - 1;
  return x > Q / 2 ? (int32_t)x - (int32_t)Q : (int32_t)x;
}

static double wall_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

int main(int argc, char **argv) {
  if (argc < 4 || argc > 7) {
    fprintf(stderr, "usage: %s signatures key_id public_constraints [secret_calibration|-] [hint-key] [start_sample]\n", argv[0]);
    return 64;
  }
  uint64_t target = strtoull(argv[1], NULL, 10);
  uint64_t start_sample = argc == 7 ? strtoull(argv[6], NULL, 0) : 0;
  unsigned key_id = (unsigned)strtoul(argv[2], NULL, 0);
  unsigned char seed[64], pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  unsigned long long pk_len = 0, sk_len = 0;
  int hint_key = argc >= 6 && strcmp(argv[5], "hint-key") == 0;
  for (unsigned i = 0; i < sizeof seed; ++i)
    seed[i] = hint_key
            ? (unsigned char)(0xb1 + i + 0x3d * key_id + (key_id >> (i & 7)))
            : (unsigned char)(0x61 + i + 0x53 * key_id + (key_id >> (i & 7)));
  if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) return 1;
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      pk_len != CRYPTO_PUBLICKEYBYTES || sk_len != CRYPTO_SECRETKEYBYTES)
    return 2;

  FILE *fp = fopen(argv[3], "wb+");
  if (!fp) { perror("constraints"); return 3; }
  constraint_header header = {0};
  memcpy(header.magic, "ATLCON1", 8);
  header.n = N;
  header.l = L;
  header.kappa = KAPPA;
  header.public_key_bytes = CRYPTO_PUBLICKEYBYTES;
  header.signatures = target;
  memcpy(header.public_key, pk, sizeof pk);
  if (fwrite(&header, sizeof header, 1, fp) != 1) return 4;

  unsigned char msg[16], sig[CRYPTO_BYTES + sizeof msg];
  polyvecl z;
  polyveck h;
  poly c;
  uint64_t rows = 0;
  double started = wall_seconds();
  const int ybound = GAMMA1 - 1;
  const int max_product = KAPPA * ETA;
  for (uint64_t sample = 0; sample < target; ++sample) {
    uint64_t global_sample = start_sample + sample;
    for (unsigned j = 0; j < sizeof msg; ++j)
      msg[j] = (unsigned char)((global_sample >> (8 * (j & 7))) ^
                               (hint_key ? (0x7b + 19 * j + key_id)
                                         : (0xd1 + 13 * j + key_id)));
    unsigned long long sig_len = 0;
    memset(sig, 0, sizeof sig);
    if (sig_sign(sk, sk_len, msg, sizeof msg, sig, &sig_len) != 0 ||
        sig_len != CRYPTO_BYTES + sizeof msg) return 5;
    unpack_sig(&z, &h, &c, sig);
    unsigned supp[KAPPA], nsupp = 0;
    for (unsigned i = 0; i < N; ++i)
      if (centered(c.coeffs[i])) supp[nsupp++] = i;
    if (nsupp != KAPPA) return 6;

    for (unsigned p = 0; p < L; ++p)
      for (unsigned j = 0; j < N; ++j) {
        int zz = centered(z.vec[p].coeffs[j]);
        int bound;
        int sense;
        if (zz >= 0) {
          bound = zz - ybound;
          sense = 1;
          if (bound <= -max_product) continue;
        } else {
          bound = zz + ybound;
          sense = -1;
          if (bound >= max_product) continue;
        }
        constraint_row row = {0};
        row.polynomial = (uint8_t)p;
        row.sense = (int8_t)sense;
        row.bound = (int16_t)bound;
        for (unsigned aa = 0; aa < nsupp; ++aa) {
          unsigned i = supp[aa];
          int ci = centered(c.coeffs[i]);
          unsigned d;
          int sign;
          if (j >= i) { d = j - i; sign = 1; }
          else { d = j + N - i; sign = -1; }
          row.row[d] = (int8_t)(sign * ci);
        }
        if (fwrite(&row, sizeof row, 1, fp) != 1) return 7;
        ++rows;
    }
    if ((sample + 1) % 10000 == 0) {
      double elapsed = wall_seconds() - started;
      printf("checkpoint=%llu/%llu constraints=%llu elapsed=%.3f sig_per_sec=%.2f\n",
             (unsigned long long)(sample + 1), (unsigned long long)target,
             (unsigned long long)rows, elapsed, (double)(sample + 1)/elapsed);
      fflush(stdout);
    }
  }
  header.constraints = rows;
  if (fseek(fp, 0, SEEK_SET) != 0 || fwrite(&header, sizeof header, 1, fp) != 1 ||
      fclose(fp) != 0) return 8;

  if (argc >= 5 && strcmp(argv[4], "-") != 0) {
    unsigned char rho[SEEDBYTES], key[SEEDBYTES], tr[CRHBYTES];
    polyvecl secret;
    polyveck t0;
    unpack_sk(rho, key, tr, &secret, &t0, sk);
    FILE *sf = fopen(argv[4], "w");
    if (!sf) return 9;
    for (unsigned p = 0; p < L; ++p) {
      for (unsigned j = 0; j < N; ++j)
        fprintf(sf, "%d%c", centered(secret.vec[p].coeffs[j]),
                j + 1 == N ? '\n' : ' ');
    }
    if (fclose(sf) != 0) return 10;
  }
  double elapsed = wall_seconds() - started;
  printf("done start_sample=%llu signatures=%llu constraints=%llu wall=%.3f sig_per_sec=%.2f public_file=%s\n",
         (unsigned long long)start_sample,
         (unsigned long long)target, (unsigned long long)rows, elapsed,
         (double)target/elapsed, argv[3]);
  return 0;
}

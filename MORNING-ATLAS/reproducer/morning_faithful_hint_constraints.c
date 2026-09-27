/* Collect the public linear model behind MORNING-ATLAS-128 hints.
 *
 * Verification obtains a = Round(Az)-c*t1*2^d and w1=UseHint(h,a).  If a0 is
 * the centered low part and dh is the centered difference High(a)-w1, then
 * u=a0+dh*alpha satisfies u=c*t0+v0 with |v0|<gamma2_bar-beta2.
 * Each record stores only public c and u values. */

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
#include "rounding.h"

#define ROUND_Q_TO_P(a) \
  (((((a) & (Q - 1)) + (1U << (QBITS - PBITS - 1)))) >> (QBITS - PBITS))

DRNG_ctx drng_algorithm;

typedef struct {
  char magic[8];
  uint32_t n, k, kappa, public_key_bytes;
  uint64_t signatures;
  unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
} hint_header;

typedef struct {
  int8_t challenge[N];
  int16_t observation[K][N];
} hint_record;

static inline int32_t centered_q(uint32_t x) {
  x &= Q - 1;
  return x > Q / 2 ? (int32_t)x - (int32_t)Q : (int32_t)x;
}

static double wall_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

int main(int argc, char **argv) {
  if (argc < 4 || argc > 5) {
    fprintf(stderr, "usage: %s signatures key_id public_observations [t0_calibration]\n", argv[0]);
    return 64;
  }
  uint64_t target = strtoull(argv[1], NULL, 10);
  unsigned key_id = (unsigned)strtoul(argv[2], NULL, 0);
  unsigned char seed[64], pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  unsigned long long pk_len = 0, sk_len = 0;
  for (unsigned i = 0; i < sizeof seed; ++i)
    seed[i] = (unsigned char)(0xb1 + i + 0x3d * key_id + (key_id >> (i & 7)));
  if (init_random_number(&drng_algorithm, seed, sizeof seed) != 0) return 1;
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      pk_len != CRYPTO_PUBLICKEYBYTES || sk_len != CRYPTO_SECRETKEYBYTES)
    return 2;

  unsigned char rho[SEEDBYTES];
  polyveck shifted_t1;
  unpack_pk(rho, &shifted_t1, pk);
  polyveck_shiftl(&shifted_t1, D);
  polyvecl mat[K];
  expand_mat(mat, rho);

  FILE *fp = fopen(argv[3], "wb");
  if (!fp) { perror("observations"); return 3; }
  hint_header header = {0};
  memcpy(header.magic, "ATLHNT1", 8);
  header.n = N;
  header.k = K;
  header.kappa = KAPPA;
  header.public_key_bytes = CRYPTO_PUBLICKEYBYTES;
  header.signatures = target;
  memcpy(header.public_key, pk, sizeof pk);
  if (fwrite(&header, sizeof header, 1, fp) != 1) return 4;

  unsigned char msg[16], sig[CRYPTO_BYTES + sizeof msg];
  polyvecl z;
  polyveck h, az, ct1;
  poly c;
  const int alpha = 2 * GAMMA2_BAR;
  const int high_modulus = P / alpha;
  double started = wall_seconds();
  for (uint64_t sample = 0; sample < target; ++sample) {
    for (unsigned j = 0; j < sizeof msg; ++j)
      msg[j] = (unsigned char)((sample >> (8 * (j & 7))) ^
                               (0x7b + 19 * j + key_id));
    unsigned long long sig_len = 0;
    memset(sig, 0, sizeof sig);
    if (sig_sign(sk, sk_len, msg, sizeof msg, sig, &sig_len) != 0 ||
        sig_len != CRYPTO_BYTES + sizeof msg) return 5;
    unpack_sig(&z, &h, &c, sig);

    polyvec_l_mul(mat, &z, &az);
    for (unsigned p = 0; p < K; ++p)
      for (unsigned j = 0; j < N; ++j)
        az.vec[p].coeffs[j] = ROUND_Q_TO_P(az.vec[p].coeffs[j]);
    for (unsigned p = 0; p < K; ++p) pol_mul(&ct1.vec[p], &c, &shifted_t1.vec[p]);
    polyveck_freeze(&ct1, Q);
    polyveck_sub(&az, &az, &ct1);
    polyveck_freeze(&az, P);

    hint_record record = {0};
    unsigned support = 0;
    for (unsigned i = 0; i < N; ++i) {
      int value = centered_q(c.coeffs[i]);
      record.challenge[i] = (int8_t)value;
      support += value != 0;
    }
    if (support != KAPPA) return 6;
    for (unsigned p = 0; p < K; ++p)
      for (unsigned j = 0; j < N; ++j) {
        uint32_t low_raw;
        int high = (int)decompose_sign(az.vec[p].coeffs[j], &low_raw);
        int low = (int)low_raw - (int)P;
        int wanted = (int)use_hint(az.vec[p].coeffs[j], h.vec[p].coeffs[j]);
        int dh = high - wanted;
        if (dh > high_modulus / 2) dh -= high_modulus;
        if (dh < -high_modulus / 2) dh += high_modulus;
        int u = low + dh * alpha;
        if (u < INT16_MIN || u > INT16_MAX) {
          fprintf(stderr, "observation overflow p=%u j=%u a=%u high=%d low=%d hint=%u wanted=%d dh=%d u=%d\n",
                  p, j, az.vec[p].coeffs[j], high, low,
                  h.vec[p].coeffs[j], wanted, dh, u);
          return 7;
        }
        record.observation[p][j] = (int16_t)u;
      }
    if (fwrite(&record, sizeof record, 1, fp) != 1) return 8;
    if ((sample + 1) % 100 == 0) {
      double elapsed = wall_seconds() - started;
      printf("checkpoint=%llu/%llu elapsed=%.3f sig_per_sec=%.2f\n",
             (unsigned long long)(sample + 1), (unsigned long long)target,
             elapsed, (double)(sample + 1)/elapsed);
      fflush(stdout);
    }
  }
  if (fclose(fp) != 0) return 9;

  if (argc == 5) {
    unsigned char key[SEEDBYTES], tr[CRHBYTES];
    polyvecl s1;
    polyveck t0;
    unpack_sk(rho, key, tr, &s1, &t0, sk);
    FILE *sf = fopen(argv[4], "w");
    if (!sf) return 10;
    for (unsigned p = 0; p < K; ++p) {
      for (unsigned j = 0; j < N; ++j)
        fprintf(sf, "%d%c", centered_q(t0.vec[p].coeffs[j]),
                j + 1 == N ? '\n' : ' ');
    }
    if (fclose(sf) != 0) return 11;
  }
  double elapsed = wall_seconds() - started;
  printf("done signatures=%llu wall=%.3f sig_per_sec=%.2f public_file=%s\n",
         (unsigned long long)target, elapsed, (double)target/elapsed, argv[3]);
  return 0;
}

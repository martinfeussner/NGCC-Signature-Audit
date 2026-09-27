/*
 * Repeated-signature public leakage collector for the DARTS-128 signing
 * distribution.  This is an audit experiment, not scheme code.
 *
 * The public signature determines z1 directly and determines z2 by the same
 * reconstruction used by Verify.  For a sparse challenge c, we accumulate the
 * normal equations for E[c^* z1].  If the hidden bimodal sign remains biased
 * after both rejection steps, the solution is a scaled copy of (s0,s1).  The
 * remaining e1 polynomial is derived and validated from the public-key
 * equation during completion.  The secret key stays inside the signing-oracle
 * simulation and is never decoded or inspected by the attack.
 */

#include <math.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "drng.h"
#include "darts_prepared_sign.h"
#include "darts_scores.h"
#include "encoding.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polymat.h"
#include "polyvec.h"
#include "reduce.h"
#include "sign.h"

extern DRNG_ctx drng_algorithm;

#define SECRET_POLYS DARTS_SECRET_POLYS

static int64_t acc[SECRET_POLYS][N];
static int64_t gram[N];

static double wall_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

static int solve_normal(double out[SECRET_POLYS][N]) {
  static double a[N][N + SECRET_POLYS];
  for (unsigned r = 0; r < N; ++r) {
    for (unsigned col = 0; col < N; ++col) {
      unsigned idx = r >= col ? r - col : r + N - col;
      int sign = r >= col ? 1 : -1;
      a[r][col] = sign * (double)gram[idx];
    }
    for (unsigned p = 0; p < SECRET_POLYS; ++p)
      a[r][N + p] = (double)acc[p][r];
  }

  for (unsigned col = 0; col < N; ++col) {
    unsigned piv = col;
    for (unsigned r = col + 1; r < N; ++r)
      if (fabs(a[r][col]) > fabs(a[piv][col])) piv = r;
    if (fabs(a[piv][col]) < 1e-12) return -1;
    if (piv != col)
      for (unsigned j = col; j < N + SECRET_POLYS; ++j) {
        double t = a[col][j];
        a[col][j] = a[piv][j];
        a[piv][j] = t;
      }
    double inv = 1.0 / a[col][col];
    for (unsigned j = col; j < N + SECRET_POLYS; ++j) a[col][j] *= inv;
    for (unsigned r = 0; r < N; ++r) {
      if (r == col || a[r][col] == 0.0) continue;
      double f = a[r][col];
      for (unsigned j = col; j < N + SECRET_POLYS; ++j)
        a[r][j] -= f * a[col][j];
    }
  }
  for (unsigned p = 0; p < SECRET_POLYS; ++p)
    for (unsigned d = 0; d < N; ++d) out[p][d] = a[d][N + p];
  return 0;
}

static inline int32_t centered_canonical(int32_t x) {
  return x > Q / 2 ? x - Q : x;
}

static int save_accumulator(const char *path, uint64_t signatures,
                            uint64_t attempts, uint64_t b0, uint64_t b1,
                            const uint8_t pk[CRYPTO_PUBLICKEYBYTES]) {
  if (!path) return 0;
  darts_accumulator_state state = {0};
  memcpy(state.magic, DARTS_STATE_MAGIC, sizeof state.magic);
  state.n = N;
  state.secret_polys = SECRET_POLYS;
  state.signatures = signatures;
  state.attempts = attempts;
  state.branch0 = b0;
  state.branch1 = b1;
  memcpy(state.public_key, pk, CRYPTO_PUBLICKEYBYTES);
  memcpy(state.acc, acc, sizeof acc);
  memcpy(state.gram, gram, sizeof gram);

  size_t path_len = strlen(path);
  char *tmp = malloc(path_len + 5);
  if (!tmp) return -1;
  memcpy(tmp, path, path_len);
  memcpy(tmp + path_len, ".tmp", 5);
  FILE *fp = fopen(tmp, "wb");
  int ok = 0;
  if (fp) {
    ok = fwrite(&state, sizeof state, 1, fp) == 1 && fflush(fp) == 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok) ok = rename(tmp, path) == 0;
  }
  if (!ok) perror("accumulator state output");
  free(tmp);
  return ok ? 0 : -1;
}

/* Decode exactly the public fields needed by the attack.  The queried signer
 * has already produced a valid fixed-size signature, so decoding the unused
 * hint would only repeat work. */
static int unpack_score_fields(poly *c, polyvecl *z1,
                               const uint8_t sig[CRYPTO_SIGNATUREBYTES]) {
  polyvecl low, high;
  for (unsigned i = 0; i < N; ++i)
    c->coeffs[i] = (sig[i / 8] >> (i % 8)) & 1;
  sig += N / 8;
  polyvecl_unpack_lowbits(&low, sig);
  sig += L * POLY_LOWBITS_PACKEDBYTES;
  uint16_t high_size = sig[0] + BASE_ENC_HB_Z1;
  uint16_t hint_size = sig[1] + BASE_ENC_H;
  sig += 2;
  if (POLY_C_PACKEDBYTES + L * POLY_LOWBITS_PACKEDBYTES + 2 +
          high_size + hint_size > CRYPTO_SIGNATUREBYTES ||
      decode_hb_z1(&high.vec[0].coeffs[0], sig, high_size))
    return -1;
  polyvecl_compose(z1, &low, &high);
  return 0;
}

static void assess(uint64_t nsig, uint64_t attempts, double elapsed,
                   unsigned key_id, const uint8_t *pk,
                   const char *score_path, uint64_t newly_collected) {
  static double theta[SECRET_POLYS][N];
  if (solve_normal(theta) != 0) {
    puts("normal matrix is singular");
    return;
  }

  printf("key=%u signatures=%llu collected=%llu attempts=%llu wall=%.3f "
         "sig_per_sec=%.1f\n",
         key_id, (unsigned long long)nsig,
         (unsigned long long)newly_collected,
         (unsigned long long)attempts, elapsed,
         (double)newly_collected / elapsed);

  if (score_path) {
    darts_score_blob blob = {0};
    memcpy(blob.magic, DARTS_SCORE_MAGIC, sizeof blob.magic);
    blob.n = N;
    blob.secret_polys = SECRET_POLYS;
    blob.signatures = nsig;
    memcpy(blob.public_key, pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(blob.theta, theta, sizeof theta);
    FILE *fp = fopen(score_path, "wb");
    if (!fp || fwrite(&blob, sizeof blob, 1, fp) != 1 || fclose(fp) != 0) {
      perror("score output");
      exit(6);
    }
    printf("public_score_file=%s bytes=%zu\n", score_path, sizeof blob);
  }
}

int main(int argc, char **argv) {
  uint64_t target = argc > 1 ? strtoull(argv[1], NULL, 10) : 1000000;
  unsigned key_id = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 0) : 0;
  const char *score_path = argc > 3 ? argv[3] : NULL;
  const char *state_path = argc > 4 ? argv[4] : NULL;
  uint64_t checkpoint_span =
      argc > 5 ? strtoull(argv[5], NULL, 10) : (state_path ? 25000 : target);
  if (!checkpoint_span) checkpoint_span = target ? target : 1;
  uint8_t seed[48], pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint64_t total_attempts = 0;
  int failed = 0;

  for (unsigned i = 0; i < sizeof(seed); ++i)
    seed[i] = (uint8_t)(0x42 + i + 0x9d * key_id + (key_id >> (i & 7)));
  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 1;
  if (crypto_sign_keypair(pk, sk) != 0) return 2;
  darts_prepared_signer signer;
  darts_prepare_signer(&signer, sk);

  uint64_t start = 0;
  if (state_path) {
    FILE *fp = fopen(state_path, "rb");
    if (fp) {
      darts_accumulator_state state;
      int ok = fread(&state, sizeof state, 1, fp) == 1 && fclose(fp) == 0 &&
               memcmp(state.magic, DARTS_STATE_MAGIC, sizeof state.magic) == 0 &&
               state.n == N && state.secret_polys == SECRET_POLYS &&
               memcmp(state.public_key, pk, CRYPTO_PUBLICKEYBYTES) == 0;
      if (!ok || state.signatures > target) {
        fputs("invalid accumulator state\n", stderr);
        return 6;
      }
      start = state.signatures;
      total_attempts = state.attempts;
      memcpy(acc, state.acc, sizeof acc);
      memcpy(gram, state.gram, sizeof gram);
      printf("resuming=%llu target=%llu state=%s\n",
             (unsigned long long)start, (unsigned long long)target, state_path);
      fflush(stdout);
    }
  }

  uint64_t resumed_at = start;
  double started = wall_seconds();
  while (start < target) {
    uint64_t end = target - start < checkpoint_span
                 ? target : start + checkpoint_span;
#pragma omp parallel reduction(+:total_attempts)
    {
      int64_t local_acc[SECRET_POLYS][N] = {{0}};
      int64_t local_gram[N] = {0};
      uint8_t sig[CRYPTO_SIGNATUREBYTES], msg[16];
      size_t siglen;
      poly c;
      polyvecl z1;
      uint64_t local_attempts = 0;

#pragma omp for schedule(static)
      for (uint64_t t = start; t < end; ++t) {
        for (unsigned j = 0; j < sizeof(msg); ++j)
          msg[j] = (uint8_t)((t >> (8 * (j % 8))) ^ (0x9d + 17 * j));
        uint64_t signature_attempts = 0;
        if (darts_prepared_signature(sig, &siglen, msg, sizeof(msg), &signer,
                                     NULL, &signature_attempts) != 0 ||
            siglen != CRYPTO_SIGNATUREBYTES ||
            unpack_score_fields(&c, &z1, sig) != 0) {
#pragma omp atomic write
          failed = 1;
          continue;
        }
        local_attempts += signature_attempts;

        unsigned supp[TAU], nsupp = 0;
        for (unsigned i = 0; i < N; ++i)
          if (c.coeffs[i]) supp[nsupp++] = i;
        if (nsupp != TAU) {
#pragma omp atomic write
          failed = 1;
          continue;
        }

        for (unsigned aa = 0; aa < nsupp; ++aa) {
          unsigned i = supp[aa];
          int ci = c.coeffs[i];
          for (unsigned p = 0; p < L; ++p) {
            const int32_t *zp = z1.vec[p].coeffs;
            int64_t *ap = local_acc[p];
            unsigned d = 0;
            for (unsigned j = i; j < N; ++j, ++d)
              ap[d] += (int64_t)ci * centered_canonical(zp[j]);
            for (unsigned j = 0; j < i; ++j, ++d)
              ap[d] -= (int64_t)ci * centered_canonical(zp[j]);
          }
        }

        for (unsigned aa = 0; aa < nsupp; ++aa) {
          unsigned i = supp[aa];
          unsigned si = i ? N - i : 0;
          int ci = (i ? -1 : 1) * c.coeffs[i];
          for (unsigned bb = 0; bb < nsupp; ++bb) {
            unsigned j = si + supp[bb];
            int sign = ci * c.coeffs[supp[bb]];
            if (j >= N) { j -= N; sign = -sign; }
            local_gram[j] += sign;
          }
        }
      }

      total_attempts += local_attempts;
#pragma omp critical
      {
        for (unsigned p = 0; p < SECRET_POLYS; ++p)
          for (unsigned d = 0; d < N; ++d) acc[p][d] += local_acc[p][d];
        for (unsigned d = 0; d < N; ++d) gram[d] += local_gram[d];
      }
    }
    if (failed) return 3;
    start = end;
    if (save_accumulator(state_path, start, total_attempts, 0, 0, pk) != 0)
      return 6;
    double elapsed = wall_seconds() - started;
    printf("checkpoint=%llu/%llu collected=%llu elapsed=%.3f "
           "sig_per_sec=%.1f attempts=%llu\n",
           (unsigned long long)start, (unsigned long long)target,
           (unsigned long long)(start - resumed_at), elapsed,
           (double)(start - resumed_at) / elapsed,
           (unsigned long long)total_attempts);
    fflush(stdout);
  }
  assess(target, total_attempts, wall_seconds() - started, key_id, pk,
         score_path, target - resumed_at);
  return 0;
}

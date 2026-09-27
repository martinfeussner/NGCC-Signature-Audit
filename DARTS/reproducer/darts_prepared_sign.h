#ifndef DARTS_PREPARED_SIGN_H
#define DARTS_PREPARED_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

/* Immutable per-key state for the submitted deterministic signer.  Preparing
 * it once only caches work that crypto_sign_signature repeats on every call:
 * secret-key unpacking, public-matrix expansion, and secret NTTs. */
typedef struct {
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t key[SEEDBYTES];
  polyvecl a[K];
  poly s0_hat;
  polyvecl_1 s1_hat;
  polyveck e_hat;
} darts_prepared_signer;

extern _Thread_local uint64_t darts_prepared_prefilter_rejects;
extern _Thread_local uint64_t darts_prepared_sphere_rejects;
extern _Thread_local uint64_t darts_prepared_packing_rejects;

void darts_prepare_signer(darts_prepared_signer *ctx,
                          const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

int darts_prepared_signature(
    uint8_t sig[CRYPTO_SIGNATUREBYTES], size_t *siglen,
    const uint8_t *message, size_t message_len,
    const darts_prepared_signer *ctx, uint8_t *accepted_b,
    uint64_t *attempt_count);

#endif

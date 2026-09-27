/*
 * A byte-for-byte equivalent batched form of the submitted DARTS signer.
 * It changes no sampling, rejection, hashing, rounding, or encoding step; it
 * only caches invariant key expansion and NTT work across messages.
 */

#include <stdint.h>
#include <string.h>

#include "darts_prepared_sign.h"
#include "packing.h"
#include "polyfix.h"
#include "polymat.h"
#include "symmetric.h"

_Thread_local uint64_t darts_prepared_prefilter_rejects;
_Thread_local uint64_t darts_prepared_sphere_rejects;
_Thread_local uint64_t darts_prepared_packing_rejects;

void darts_prepare_signer(darts_prepared_signer *ctx,
                          const uint8_t sk[CRYPTO_SECRETKEYBYTES]) {
  memcpy(ctx->pk, sk, CRYPTO_PUBLICKEYBYTES);
  unpack_sk(ctx->a, &ctx->s0_hat, &ctx->s1_hat, &ctx->e_hat, ctx->key, sk);
  poly_ntt(&ctx->s0_hat);
  polyvecl_1_ntt(&ctx->s1_hat);
  polyveck_ntt(&ctx->e_hat);
}

int darts_prepared_signature(
    uint8_t sig[CRYPTO_SIGNATUREBYTES], size_t *siglen,
    const uint8_t *message, size_t message_len,
    const darts_prepared_signer *ctx, uint8_t *accepted_b,
    uint64_t *attempt_count) {
  uint8_t buf[POLYVECK_HIGHBITS_PACKEDBYTES] = {0};
  uint8_t seedbuf[CRHBYTES] = {0};
  uint8_t mu[CRHBYTES] = {0};
  uint8_t b;
  uint16_t counter = 0;
  uint64_t attempts = 0;

  polyveck w, h, htmp;
  polyfixvecl y1, z1, z1tmp;
  polyfixveck y2, z2, z2tmp;
  polyvecl z1rnd, highbits_z1, lowbits_z1, cs;
  polyveck z2rnd, ce;
  poly c, c_hat, c_1_b, w0, w0_highbits, w0_cb, w0_cb_highbits;
  sm3_xof_state state;

  sm3_xof_absorb_twice(&state, ctx->pk, CRYPTO_PUBLICKEYBYTES,
                       message, message_len);
  sm3_xof_squeeze(mu, CRHBYTES, &state);
  sm3_xof_absorb_twice(&state, ctx->key, SEEDBYTES, mu, CRHBYTES);
  sm3_xof_squeeze(seedbuf, CRHBYTES, &state);

reject:
  ++attempts;
  counter = polyfixveclk_sample_hyperball(&y1, &y2, &b, seedbuf, counter);

  polyfixvecl_round(&z1rnd, &y1);
  polyfixveck_round(&z2rnd, &y2);

  polyvecl_ntt(&z1rnd);
  polymatkl_pointwise_montgomery(&w, ctx->a, &z1rnd);
  polyveck_invntt_tomont(&w);
  polyveck_add(&w, &w, &z2rnd);
  polyveck_freeze(&w);

  polyveck_pack_highbits(buf, &w);
  poly_challenge(&c, buf, mu);

  w0 = w.vec[0];
  poly_mul_1_b(&c_1_b, &c, b & 1);
  poly_add(&w0_cb, &w0, &c_1_b);
  poly_freeze(&w0);
  poly_freeze(&w0_cb);
  poly_compress(&w0_highbits, &w0);
  poly_compress(&w0_cb_highbits, &w0_cb);
  if (!poly_equal(&w0_highbits, &w0_cb_highbits)) {
    ++darts_prepared_prefilter_rejects;
    goto reject;
  }

  c_hat = c;
  poly_ntt(&c_hat);
  poly_basemul_montgomery(&cs.vec[0], &c_hat, &ctx->s0_hat);
  for (unsigned i = 0; i < L - 1; ++i)
    poly_basemul_montgomery(&cs.vec[i + 1], &c_hat,
                            &ctx->s1_hat.vec[i]);
  for (unsigned i = 0; i < K; ++i)
    poly_basemul_montgomery(&ce.vec[i], &c_hat, &ctx->e_hat.vec[i]);
  polyvecl_invntt_tomont(&cs);
  polyveck_invntt_tomont(&ce);

  polyvecl_cneg(&cs, b & 1);
  polyveck_cneg(&ce, b & 1);
  polyfixvecl_add(&z1, &y1, &cs);
  polyfixveck_add(&z2, &y2, &ce);

  uint64_t reject1 =
      ((uint64_t)B1SQ * LN * LN - polyfixveclk_sqnorm2(&z1, &z2)) >> 63;
  polyfixvecl_double(&z1tmp, &z1);
  polyfixveck_double(&z2tmp, &z2);
  polyfixfixvecl_sub(&z1tmp, &z1tmp, &y1);
  polyfixfixveck_sub(&z2tmp, &z2tmp, &y2);
  uint64_t reject2 =
      (polyfixveclk_sqnorm2(&z1tmp, &z2tmp) - BSQ * LN * LN) >> 63;
  uint64_t reject3 =
      ((uint64_t)B0SQ * LN * LN - polyfixveclk_sqnorm2(&z1, &z2)) >> 63;
  if ((reject1 & 1) || ((reject2 & 1) && (reject3 & 1) && !(b & 2))) {
    ++darts_prepared_sphere_rejects;
    goto reject;
  }

  polyfixvecl_round(&z1rnd, &z1);
  polyfixveck_round(&z2rnd, &z2);
  polyvecl_freeze(&z1rnd);
  polyveck_freeze(&z2rnd);
  polyvecl_lowbits(&lowbits_z1, &z1rnd);
  polyvecl_compress(&highbits_z1, &z1rnd);

  polyveck_compress(&htmp, &w);
  polyveck_sub(&w, &w, &z2rnd);
  poly_add(&w.vec[0], &w.vec[0], &c_1_b);
  polyveck_freeze(&w);
  polyveck_compress(&h, &w);
  polyveck_sub(&h, &htmp, &h);
  if (pack_sig(sig, &c, &lowbits_z1, &highbits_z1, &h)) {
    ++darts_prepared_packing_rejects;
    goto reject;
  }

  *siglen = CRYPTO_SIGNATUREBYTES;
  if (accepted_b) *accepted_b = b;
  if (attempt_count) *attempt_count = attempts;
  return 0;
}

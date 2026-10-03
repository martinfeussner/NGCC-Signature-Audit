#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "canonical.h"
#include "hashkdf.h"
#include "hostile_api.h"
#include "matrixmod.h"
#include "params.h"
#include "randombytes.h"
#include "triform.h"
#include "trine_codec.h"
#include "trine_expand.h"
#include "util.h"

#define MAX_SIGNATURES 24

/* The submitted normal RNG header omits this declaration.  Calling it here
 * explicitly avoids relying on the separately reported zero-state RNG bug. */
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength);

typedef struct {
  int valid;
  Fq A[TRINE_n * TRINE_n];
  Fq B[TRINE_n * TRINE_n];
  Fq C[TRINE_n * TRINE_n];
} edge_map;

static const Fq *form_at(const Fq *base, const Fq *nonbase, int label)
{
  if (label == TRINE_X)
    return base;
  return nonbase + (size_t)label * triform_element_count(TRINE_n);
}

static int form_equal(const Fq *a, const Fq *b)
{
  return memcmp(a, b, triform_element_count(TRINE_n) * sizeof(*a)) == 0;
}

static void map_identity(edge_map *m)
{
  m->valid = 1;
  pmod_mat_identity(m->A, TRINE_n);
  pmod_mat_identity(m->B, TRINE_n);
  pmod_mat_identity(m->C, TRINE_n);
}

static int map_inverse(edge_map *out, const edge_map *in)
{
  if (pmod_mat_inv(out->A, in->A, TRINE_n, TRINE_n) != 0 ||
      pmod_mat_inv(out->B, in->B, TRINE_n, TRINE_n) != 0 ||
      pmod_mat_inv(out->C, in->C, TRINE_n, TRINE_n) != 0)
    return -1;
  out->valid = 1;
  return 0;
}

static void map_compose(edge_map *out, const edge_map *left, const edge_map *right)
{
  pmod_mat_mul(out->A, left->A, right->A, TRINE_n);
  pmod_mat_mul(out->B, left->B, right->B, TRINE_n);
  pmod_mat_mul(out->C, left->C, right->C, TRINE_n);
  out->valid = 1;
}

static int relation_holds(
    const Fq *from,
    const Fq *to,
    const edge_map *map)
{
  const size_t count = triform_element_count(TRINE_n);
  Fq *got = malloc(count * sizeof(*got));
  if (got == NULL)
    return 0;
  triform_action_pullback(got, from, map->A, map->B, map->C, TRINE_n);
  const int ok = form_equal(got, to);
  free(got);
  return ok;
}

static int extract_edge(
    edge_map *out,
    const Fq *form_u,
    const Fq *point_u,
    const Fq *form_v,
    const Fq *point_v)
{
  const size_t form_count = triform_element_count(TRINE_n);
  const size_t matrix_count = (size_t)TRINE_n * TRINE_n;
  Fq *cf_u = malloc(form_count * sizeof(*cf_u));
  Fq *cf_v = malloc(form_count * sizeof(*cf_v));
  Fq *Tu = malloc(3u * matrix_count * sizeof(*Tu));
  Fq *Tv = malloc(3u * matrix_count * sizeof(*Tv));
  Fq *inv = malloc(3u * matrix_count * sizeof(*inv));
  if (!cf_u || !cf_v || !Tu || !Tv || !inv)
    return -1;

  int ret = -1;
  if (canonical_form_with_certificate_vartime(
          cf_u, Tu, Tu + matrix_count, Tu + 2u * matrix_count,
          form_u, point_u, TRINE_n) != 0 ||
      canonical_form_with_certificate_vartime(
          cf_v, Tv, Tv + matrix_count, Tv + 2u * matrix_count,
          form_v, point_v, TRINE_n) != 0 ||
      !form_equal(cf_u, cf_v))
    goto cleanup;

  for (int component = 0; component < 3; component++)
    if (pmod_mat_inv(
            inv + (size_t)component * matrix_count,
            Tv + (size_t)component * matrix_count,
            TRINE_n, TRINE_n) != 0)
      goto cleanup;

  pmod_mat_mul(out->A, Tu, inv, TRINE_n);
  pmod_mat_mul(out->B, Tu + matrix_count, inv + matrix_count, TRINE_n);
  pmod_mat_mul(out->C, Tu + 2u * matrix_count, inv + 2u * matrix_count, TRINE_n);
  out->valid = 1;
  ret = relation_holds(form_u, form_v, out) ? 0 : -1;

cleanup:
  free(cf_u); free(cf_v); free(Tu); free(Tv); free(inv);
  return ret;
}

static void graph_close(edge_map maps[TRINE_FORM_COUNT][TRINE_FORM_COUNT])
{
  for (int changed = 1; changed; )
  {
    changed = 0;
    for (int i = 0; i < TRINE_FORM_COUNT; i++)
      for (int k = 0; k < TRINE_FORM_COUNT; k++)
        for (int j = 0; j < TRINE_FORM_COUNT; j++)
          if (!maps[i][j].valid && maps[i][k].valid && maps[k][j].valid)
          {
            map_compose(&maps[i][j], &maps[i][k], &maps[k][j]);
            changed = 1;
          }
  }
}

static int graph_complete_from_base(
    edge_map maps[TRINE_FORM_COUNT][TRINE_FORM_COUNT])
{
  for (int j = 0; j < TRINE_X; j++)
    if (!maps[TRINE_X][j].valid)
      return 0;
  return 1;
}

static int forge_with_maps(
    uint8_t *sig,
    const uint8_t *message,
    size_t message_len,
    const Fq *base_form,
    edge_map maps[TRINE_FORM_COUNT][TRINE_FORM_COUNT])
{
  const size_t form_count = triform_element_count(TRINE_n);
  Fq *a_all = calloc((size_t)TRINE_r * TRINE_n, sizeof(*a_all));
  Fq *psi = malloc(form_count * sizeof(*psi));
  Fq *responses = calloc((size_t)TRINE_K * TRINE_n, sizeof(*responses));
  uint8_t *round_seeds = calloc((size_t)TRINE_r, TRINE_round_seed_bytes);
  uint8_t *base_seeds = calloc(TRINE_BASE_SEED_BYTES, 1);
  uint8_t *encoded = malloc(TRINE_TRIFORM_BYTES);
  if (!a_all || !psi || !responses || !round_seeds || !base_seeds || !encoded)
    return -1;

  uint8_t digest[TRINE_digest_bytes];
  uint8_t salt[TRINE_salt_bytes] = {0};
  trine_challenge_t challenges[TRINE_r];
  edge_map inverse[TRINE_X];
  trine_hash_state transcript;
  int active = 0;
  int ret = -1;

  for (int j = 0; j < TRINE_X; j++)
    if (map_inverse(&inverse[j], &maps[TRINE_X][j]) != 0)
      goto cleanup;

  if (randombytes(round_seeds,
          (unsigned long long)TRINE_r * TRINE_round_seed_bytes) != RANDOMBYTES_SUCCESS)
    goto cleanup;
  if (trine_hash_init(&transcript) != 0)
    goto cleanup;
  active = 1;
  if (message_len && trine_hash_absorb(&transcript, message, message_len) != 0)
    goto cleanup;

  for (int round = 0; round < TRINE_r; round++)
  {
    Fq *a = a_all + (size_t)round * TRINE_n;
    const uint8_t *seed = round_seeds + (size_t)round * TRINE_round_seed_bytes;
    if (hostile_derive_round_commitment_vartime(
            a, psi, base_form, seed, (uint32_t)round) != 0 ||
        trine_codec_encode_triform(encoded, TRINE_TRIFORM_BYTES, psi, TRINE_n) != 0 ||
        trine_hash_absorb(&transcript, encoded, TRINE_TRIFORM_BYTES) != 0)
      goto cleanup;
  }
  if (trine_hash_finalize(&transcript, digest, sizeof(digest)) != 0)
    goto cleanup;
  trine_hash_release(&transcript); active = 0;
  if (trine_parse_hash(digest, sizeof(digest), challenges, TRINE_r) != 0)
    goto cleanup;

  size_t response_index = 0, base_index = 0;
  for (int round = 0; round < TRINE_r; round++)
  {
    const int label = challenges[round];
    const Fq *a = a_all + (size_t)round * TRINE_n;
    if (label < TRINE_X)
    {
      pmod_mat_vec_mul(
          responses + response_index * TRINE_n,
          inverse[label].A, a, TRINE_n);
      response_index++;
    }
    else
    {
      memcpy(base_seeds + base_index * TRINE_round_seed_bytes,
             round_seeds + (size_t)round * TRINE_round_seed_bytes,
             TRINE_round_seed_bytes);
      base_index++;
    }
  }
  if (response_index != TRINE_K || base_index != TRINE_BASE_SEED_COUNT)
    goto cleanup;
  if (trine_codec_encode_signature(
          sig, TRINE_SIG_BYTES, responses, base_seeds, digest, salt) != 0)
    goto cleanup;
  ret = 0;

cleanup:
  if (active) trine_hash_release(&transcript);
  free(a_all); free(psi); free(responses); free(round_seeds);
  free(base_seeds); free(encoded);
  return ret;
}

static int run_one(int key_number)
{
  const size_t form_count = triform_element_count(TRINE_n);
  const size_t records = (size_t)MAX_SIGNATURES * TRINE_r;
  uint8_t *pk = malloc(TRINE_PK_BYTES);
  uint8_t *sk = malloc(TRINE_SK_BYTES);
  uint8_t public_seed[TRINE_public_seed_bytes];
  Fq *base = malloc(form_count * sizeof(*base));
  Fq *nonbase = malloc((size_t)TRINE_X * form_count * sizeof(*nonbase));
  int16_t *labels = malloc(records * sizeof(*labels));
  Fq *points = malloc(records * TRINE_n * sizeof(*points));
  Fq *cfs = malloc(records * form_count * sizeof(*cfs));
  if (!pk || !sk || !base || !nonbase || !labels || !points || !cfs)
    return -1;

  edge_map maps[TRINE_FORM_COUNT][TRINE_FORM_COUNT];
  memset(maps, 0, sizeof(maps));
  for (int i = 0; i < TRINE_FORM_COUNT; i++) map_identity(&maps[i][i]);

  if (crypto_sign_keypair(pk, sk) != 0 ||
      trine_codec_decode_public_key_checked(public_seed, nonbase, pk, TRINE_PK_BYTES) != 0 ||
      trine_expand_base_form(base, public_seed, TRINE_n) != 0)
    return -1;

  int used_signatures = 0, collision_edges = 0;
  for (int s = 0; s < MAX_SIGNATURES && !graph_complete_from_base(maps); s++)
  {
    char message[64];
    const int message_len = snprintf(message, sizeof(message),
        "hostile-query-key-%d-signature-%d", key_number, s);
    uint8_t *sm = malloc(TRINE_SIG_BYTES + (size_t)message_len);
    Fq *responses = malloc((size_t)TRINE_K * TRINE_n * sizeof(*responses));
    uint8_t *base_seeds = malloc(TRINE_BASE_SEED_BYTES);
    uint8_t digest[TRINE_digest_bytes], salt[TRINE_salt_bytes];
    trine_challenge_t challenges[TRINE_r];
    unsigned long long smlen = 0;
    if (!sm || !responses || !base_seeds ||
        crypto_sign(sm, &smlen, (const uint8_t *)message, (unsigned long long)message_len, sk) != 0 ||
        smlen != TRINE_SIG_BYTES + (unsigned long long)message_len ||
        (s == 0 && crypto_sign_verify(sm, TRINE_SIG_BYTES,
            (const uint8_t *)message, (unsigned long long)message_len, pk) != 0) ||
        trine_codec_decode_signature_checked(
            responses, base_seeds, digest, salt, sm, TRINE_SIG_BYTES) != 0 ||
        trine_parse_hash(digest, sizeof(digest), challenges, TRINE_r) != 0)
      return -1;
    for (size_t z = 0; z < sizeof(salt); z++)
      if (salt[z] != 0) return -1;

    size_t ri = 0, bi = 0;
    for (int round = 0; round < TRINE_r; round++)
    {
      const size_t rec = (size_t)s * TRINE_r + (size_t)round;
      const int label = challenges[round];
      Fq *point = points + rec * TRINE_n;
      Fq *cf = cfs + rec * form_count;
      labels[rec] = (int16_t)label;
      if (label < TRINE_X)
      {
        memcpy(point, responses + ri * TRINE_n, TRINE_n * sizeof(*point));
        ri++;
        if (canonical_form_vartime(
                cf, form_at(base, nonbase, label), point, TRINE_n) != 0)
          return -1;
      }
      else
      {
        const uint8_t *seed = base_seeds + bi * TRINE_round_seed_bytes;
        if (hostile_derive_round_commitment_vartime(
                point, cf, base, seed, (uint32_t)round) != 0)
          return -1;
        bi++;
      }

      for (int old_s = 0; old_s < s; old_s++)
      {
        const size_t old = (size_t)old_s * TRINE_r + (size_t)round;
        const int old_label = labels[old];
        if (old_label == label || maps[old_label][label].valid ||
            !form_equal(cfs + old * form_count, cf))
          continue;
        edge_map edge, reverse;
        memset(&edge, 0, sizeof(edge)); memset(&reverse, 0, sizeof(reverse));
        if (extract_edge(
                &edge,
                form_at(base, nonbase, old_label), points + old * TRINE_n,
                form_at(base, nonbase, label), point) != 0 ||
            map_inverse(&reverse, &edge) != 0)
          return -1;
        maps[old_label][label] = edge;
        maps[label][old_label] = reverse;
        collision_edges++;
        graph_close(maps);
      }
    }
    if (ri != TRINE_K || bi != TRINE_BASE_SEED_COUNT)
      return -1;
    used_signatures = s + 1;
    free(sm); free(responses); free(base_seeds);
  }

  if (!graph_complete_from_base(maps))
  {
    fprintf(stderr, "graph did not connect within %d signatures\n", MAX_SIGNATURES);
    return -1;
  }
  for (int j = 0; j < TRINE_X; j++)
    if (!relation_holds(base, form_at(base, nonbase, j), &maps[TRINE_X][j]))
      return -1;

  /* Erase the original signing seed and every collected transcript value. */
  memset(sk, 0, TRINE_SK_BYTES);
  memset(points, 0, records * TRINE_n * sizeof(*points));
  memset(cfs, 0, records * form_count * sizeof(*cfs));
  memset(labels, 0, records * sizeof(*labels));

  const char *fresh = "hostile-fresh-message-never-queried";
  uint8_t *forgery = malloc(TRINE_SIG_BYTES);
  uint8_t *tampered = malloc(TRINE_SIG_BYTES);
  if (!forgery || !tampered ||
      forge_with_maps(forgery, (const uint8_t *)fresh, strlen(fresh), base, maps) != 0)
    return -1;
  const int accepted = crypto_sign_verify(
      forgery, TRINE_SIG_BYTES, (const uint8_t *)fresh, strlen(fresh), pk) == 0;
  const int wrong_message_rejected = crypto_sign_verify(
      forgery, TRINE_SIG_BYTES, (const uint8_t *)"wrong-message", 13, pk) != 0;
  memcpy(tampered, forgery, TRINE_SIG_BYTES);
  tampered[0] ^= 1u;
  const int response_tamper_rejected = crypto_sign_verify(
      tampered, TRINE_SIG_BYTES, (const uint8_t *)fresh, strlen(fresh), pk) != 0;
  memcpy(tampered, forgery, TRINE_SIG_BYTES);
  tampered[TRINE_SIG_BYTES - 1u] ^= 1u;
  const int digest_tamper_rejected = crypto_sign_verify(
      tampered, TRINE_SIG_BYTES, (const uint8_t *)fresh, strlen(fresh), pk) != 0;

  printf("{\"profile\":\"%s\",\"key\":%d,\"reduced_seed_bits\":%d,"
         "\"signatures\":%d,\"collision_edges\":%d,"
         "\"fresh_forgery_accepted\":%s,\"wrong_message_rejected\":%s,"
         "\"response_tamper_rejected\":%s,\"digest_tamper_rejected\":%s,"
         "\"spec_signature_bytes\":%d,"
         "\"secret_erased_before_forge\":true,\"drbg_explicitly_initialized\":true}\n",
      TRINE_PARAMETER_SET_NAME, key_number, HOSTILE_REDUCED_SEED_BITS,
      used_signatures, collision_edges,
      accepted ? "true" : "false",
      wrong_message_rejected ? "true" : "false",
      response_tamper_rejected ? "true" : "false",
      digest_tamper_rejected ? "true" : "false", TRINE_SIG_BYTES);

  free(pk); free(sk); free(base); free(nonbase); free(labels); free(points);
  free(cfs); free(forgery); free(tampered);
  return accepted && wrong_message_rejected && response_tamper_rejected &&
         digest_tamper_rejected ? 0 : -1;
}

int main(void)
{
  uint8_t entropy[48];
  for (size_t i = 0; i < sizeof(entropy); i++)
    entropy[i] = (uint8_t)(0x5bu + 37u * i);
  randombytes_init(entropy, NULL, 256);
  memset(entropy, 0, sizeof(entropy));
  for (int key = 0; key < 2; key++)
    if (run_one(key) != 0)
      return 1;
  return 0;
}

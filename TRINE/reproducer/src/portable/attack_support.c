#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "canonical.h"
#include "corank1.h"
#include "field.h"
#include "hashkdf.h"
#include "matrixelim.h"
#include "matrixmod.h"
#include "params.h"
#include "triform.h"
#include "trine_codec.h"
#include "trine_expand.h"
#include "util.h"

/* PDF Section 3.5: no submitted-code salt field. */
#define PDF_SIG_BYTES \
  (TRINE_RESPONSE_BYTES + TRINE_BASE_SEED_BYTES + TRINE_digest_bytes)
#define PDF_RESPONSE_OFFSET 0u
#define PDF_BASE_SEED_OFFSET TRINE_RESPONSE_BYTES
#define PDF_DIGEST_OFFSET (TRINE_RESPONSE_BYTES + TRINE_BASE_SEED_BYTES)

static const uint8_t ROUND_DOMAIN[] = "MEDS2END-TRINE-ROUND-v1";

typedef struct
{
  uint8_t seeds[TRINE_r * TRINE_round_seed_bytes];
  Fq a[TRINE_r * TRINE_n];
  uint8_t encoded_psi[TRINE_r * TRINE_TRIFORM_BYTES];
} commitment_batch;

static double now_seconds(void)
{
  struct timespec ts;
  (void)clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

static int bytes_from_label(uint8_t *out, size_t out_len, const char *label)
{
  return trine_xof_once(out, out_len, (const uint8_t *)label, strlen(label));
}

static int hash_equal(const void *a, const void *b, size_t len)
{
  return memcmp(a, b, len) == 0;
}

static int fq_equal(const Fq *a, const Fq *b, size_t count)
{
  return memcmp(a, b, count * sizeof(*a)) == 0;
}

/*
 * The PDF specifies lambda-bit seeds for base openings but leaves their PRG
 * formatting implicit.  This is the submitted derivation with only the
 * source-only 2*lambda-bit salt removed.  It realizes the PDF distribution:
 * sample uniformly until Corank1Cal and CF both succeed.
 */
static int init_pdf_round_xof(
    trine_xof_state *xof,
    const uint8_t seed[TRINE_round_seed_bytes],
    uint32_t round)
{
  uint8_t le[4] = {
      (uint8_t)round,
      (uint8_t)(round >> 8),
      (uint8_t)(round >> 16),
      (uint8_t)(round >> 24)};

  if (trine_xof_init(xof) != 0 ||
      trine_xof_absorb(xof, ROUND_DOMAIN, sizeof(ROUND_DOMAIN) - 1u) != 0 ||
      trine_xof_absorb(xof, seed, TRINE_round_seed_bytes) != 0 ||
      trine_xof_absorb(xof, le, sizeof(le)) != 0 ||
      trine_xof_finalize(xof) != 0)
  {
    trine_xof_release(xof);
    return -1;
  }
  return 0;
}

static int derive_pdf_commitment(
    Fq *out_a,
    Fq *out_psi,
    const Fq *base,
    const uint8_t seed[TRINE_round_seed_bytes],
    uint32_t round)
{
  trine_xof_state xof;
  Fq a[TRINE_n];

  if (init_pdf_round_xof(&xof, seed, round) != 0)
    return -1;

  for (;;)
  {
    if (corank1_cal_vartime(a, base, &xof, TRINE_n) != 0)
    {
      trine_xof_release(&xof);
      return -1;
    }
    if (canonical_form_vartime(out_psi, base, a, TRINE_n) == 0)
      break;
  }
  trine_xof_release(&xof);
  if (out_a != NULL)
    memcpy(out_a, a, sizeof(a));
  return 0;
}

static int build_batch(
    commitment_batch *batch,
    const Fq *base,
    const char *seed_label)
{
  const size_t form_elems = triform_element_count(TRINE_n);
  Fq *psi = malloc(form_elems * sizeof(*psi));
  if (psi == NULL)
    return -1;

  if (bytes_from_label(batch->seeds, sizeof(batch->seeds), seed_label) != 0)
  {
    free(psi);
    return -1;
  }

  for (uint32_t i = 0; i < (uint32_t)TRINE_r; i++)
  {
    Fq *a = batch->a + (size_t)i * TRINE_n;
    uint8_t *encoded = batch->encoded_psi + (size_t)i * TRINE_TRIFORM_BYTES;
    const uint8_t *seed = batch->seeds + (size_t)i * TRINE_round_seed_bytes;
    if (derive_pdf_commitment(a, psi, base, seed, i) != 0 ||
        trine_codec_encode_triform(
            encoded, TRINE_TRIFORM_BYTES, psi, TRINE_n) != 0)
    {
      free(psi);
      return -1;
    }
  }

  free(psi);
  return 0;
}

static int transcript_digest(
    uint8_t digest[TRINE_digest_bytes],
    const uint8_t *message,
    size_t message_len,
    const commitment_batch *batch)
{
  trine_hash_state h;
  if (trine_hash_init(&h) != 0)
    return -1;
  if ((message_len != 0u && trine_hash_absorb(&h, message, message_len) != 0))
  {
    trine_hash_release(&h);
    return -1;
  }
  for (size_t i = 0; i < TRINE_r; i++)
    if (trine_hash_absorb(
            &h,
            batch->encoded_psi + i * TRINE_TRIFORM_BYTES,
            TRINE_TRIFORM_BYTES) != 0)
    {
      trine_hash_release(&h);
      return -1;
    }
  if (trine_hash_finalize(&h, digest, TRINE_digest_bytes) != 0)
  {
    trine_hash_release(&h);
    return -1;
  }
  trine_hash_release(&h);
  return 0;
}

static int encode_pdf_signature(
    uint8_t sig[PDF_SIG_BYTES],
    const Fq responses[TRINE_K * TRINE_n],
    const uint8_t base_seeds[TRINE_BASE_SEED_BYTES],
    const uint8_t digest[TRINE_digest_bytes])
{
  if (trine_codec_encode_fq_array(
          sig + PDF_RESPONSE_OFFSET,
          TRINE_RESPONSE_BYTES,
          responses,
          (size_t)TRINE_K * TRINE_n) != 0)
    return -1;
  memcpy(sig + PDF_BASE_SEED_OFFSET, base_seeds, TRINE_BASE_SEED_BYTES);
  memcpy(sig + PDF_DIGEST_OFFSET, digest, TRINE_digest_bytes);
  return 0;
}

static int decode_pdf_signature(
    Fq responses[TRINE_K * TRINE_n],
    uint8_t base_seeds[TRINE_BASE_SEED_BYTES],
    uint8_t digest[TRINE_digest_bytes],
    const uint8_t sig[PDF_SIG_BYTES])
{
  if (trine_codec_decode_fq_array_checked(
          responses,
          (size_t)TRINE_K * TRINE_n,
          sig + PDF_RESPONSE_OFFSET,
          TRINE_RESPONSE_BYTES) != 0)
    return -1;
  memcpy(base_seeds, sig + PDF_BASE_SEED_OFFSET, TRINE_BASE_SEED_BYTES);
  memcpy(digest, sig + PDF_DIGEST_OFFSET, TRINE_digest_bytes);
  return 0;
}

/* map_A is a public-form-to-base map: phi_0^(map_A,map_B,map_C)=phi_X. */
static int sign_from_batch(
    uint8_t sig[PDF_SIG_BYTES],
    trine_challenge_t challenges[TRINE_r],
    const uint8_t *message,
    size_t message_len,
    const commitment_batch *batch,
    const Fq map_A[TRINE_n * TRINE_n])
{
  uint8_t digest[TRINE_digest_bytes];
  Fq responses[TRINE_K * TRINE_n];
  uint8_t base_seeds[TRINE_BASE_SEED_BYTES];
  size_t ri = 0, si = 0;

  if (transcript_digest(digest, message, message_len, batch) != 0 ||
      trine_parse_hash(digest, sizeof(digest), challenges, TRINE_r) != 0)
    return -1;

  for (size_t i = 0; i < TRINE_r; i++)
  {
    if (challenges[i] == 0)
    {
      pmod_mat_vec_mul(
          responses + ri * TRINE_n,
          map_A,
          batch->a + i * TRINE_n,
          TRINE_n);
      ri++;
    }
    else if (challenges[i] == TRINE_BASE_FORM_INDEX)
    {
      memcpy(
          base_seeds + si * TRINE_round_seed_bytes,
          batch->seeds + i * TRINE_round_seed_bytes,
          TRINE_round_seed_bytes);
      si++;
    }
    else
      return -1;
  }

  if (ri != TRINE_K || si != TRINE_BASE_SEED_COUNT)
    return -1;
  return encode_pdf_signature(sig, responses, base_seeds, digest);
}

/* Independent repaired verifier for Algorithms 7--8 and Section 3.4. */
static int verify_pdf_signature(
    const uint8_t sig[PDF_SIG_BYTES],
    const uint8_t *message,
    size_t message_len,
    const uint8_t pk[TRINE_PK_BYTES])
{
  int ret = -1;
  const size_t form_elems = triform_element_count(TRINE_n);
  uint8_t public_seed[TRINE_public_seed_bytes];
  uint8_t digest[TRINE_digest_bytes], digest2[TRINE_digest_bytes];
  uint8_t base_seeds[TRINE_BASE_SEED_BYTES];
  trine_challenge_t challenge[TRINE_r], challenge2[TRINE_r];
  Fq responses[TRINE_K * TRINE_n];
  Fq *base = malloc(form_elems * sizeof(*base));
  Fq *nonbase = malloc(form_elems * sizeof(*nonbase));
  Fq *psi = malloc(form_elems * sizeof(*psi));
  uint8_t *encoded = malloc(TRINE_TRIFORM_BYTES);
  trine_hash_state h;
  int h_active = 0;
  size_t ri = 0, si = 0;

  if (base == NULL || nonbase == NULL || psi == NULL || encoded == NULL)
    goto done;
  if (trine_codec_decode_public_key_checked(
          public_seed, nonbase, pk, TRINE_PK_BYTES) != 0 ||
      trine_expand_base_form(base, public_seed, TRINE_n) != 0 ||
      decode_pdf_signature(responses, base_seeds, digest, sig) != 0 ||
      trine_parse_hash(digest, sizeof(digest), challenge, TRINE_r) != 0)
    goto done;

  if (trine_hash_init(&h) != 0)
    goto done;
  h_active = 1;
  if (message_len != 0u && trine_hash_absorb(&h, message, message_len) != 0)
    goto done;

  for (uint32_t i = 0; i < (uint32_t)TRINE_r; i++)
  {
    if (challenge[i] == 0)
    {
      if (ri >= TRINE_K ||
          canonical_form_vartime(
              psi, nonbase, responses + ri * TRINE_n, TRINE_n) != 0)
        goto done;
      ri++;
    }
    else if (challenge[i] == TRINE_BASE_FORM_INDEX)
    {
      if (si >= TRINE_BASE_SEED_COUNT ||
          derive_pdf_commitment(
              NULL,
              psi,
              base,
              base_seeds + si * TRINE_round_seed_bytes,
              i) != 0)
        goto done;
      si++;
    }
    else
      goto done;

    if (trine_codec_encode_triform(
            encoded, TRINE_TRIFORM_BYTES, psi, TRINE_n) != 0 ||
        trine_hash_absorb(&h, encoded, TRINE_TRIFORM_BYTES) != 0)
      goto done;
  }

  if (ri != TRINE_K || si != TRINE_BASE_SEED_COUNT ||
      trine_hash_finalize(&h, digest2, sizeof(digest2)) != 0)
    goto done;
  h_active = 0;
  trine_hash_release(&h);
  if (trine_parse_hash(digest2, sizeof(digest2), challenge2, TRINE_r) != 0)
    goto done;
  ret = memcmp(challenge, challenge2, sizeof(challenge)) == 0 ? 0 : -1;

done:
  if (h_active)
    trine_hash_release(&h);
  free(base);
  free(nonbase);
  free(psi);
  free(encoded);
  return ret;
}

static void collect_anchors(Fq *anchors, const Fq *m, int n)
{
  const size_t aoff = 0;
  const size_t boff = (size_t)(n - 2);
  const size_t coff = 2u * (size_t)(n - 2);
  const size_t doff = 3u * (size_t)(n - 2);
  const Fq *m1 = triform_slice_const(m, 0, n);
  const Fq *m2 = triform_slice_const(m, 1, n);
  const Fq *m5 = triform_slice_const(m, 4, n);

  for (int i = 2; i < n; i++)
  {
    const size_t o = (size_t)(i - 2);
    anchors[aoff + o] = m1[(size_t)i * n + 1u];
    anchors[boff + o] = m1[i];
    anchors[coff + o] = triform_slice_const(m, i, n)[1];
  }
  anchors[doff + 0u] = m1[1];
  anchors[doff + 1u] = m5[(size_t)n + 2u];
  anchors[doff + 2u] = m2[2];
  anchors[doff + 3u] = m2[n];
}

static int normalization_diagonals(
    Fq f[TRINE_n], Fq g[TRINE_n], Fq h[TRINE_n], const Fq *transformed)
{
  const size_t n = TRINE_n;
  const size_t count = 3u * n - 2u;
  const size_t aoff = 0;
  const size_t boff = n - 2u;
  const size_t coff = 2u * (n - 2u);
  const size_t doff = 3u * (n - 2u);
  Fq anchors[3 * TRINE_n - 2], inv[3 * TRINE_n - 2];

  collect_anchors(anchors, transformed, TRINE_n);
  if (GF_batch_inv(inv, anchors, count) != 0)
    return -1;
  const Fq d1 = anchors[doff], d2 = anchors[doff + 1u];
  const Fq d3 = anchors[doff + 2u];
  const Fq id1 = inv[doff], id2 = inv[doff + 1u];
  const Fq id3 = inv[doff + 2u], id4 = inv[doff + 3u];

  f[0] = 1;
  g[1] = 1;
  h[0] = id1;
  for (size_t i = 2; i < n; i++)
  {
    const size_t o = i - 2u;
    f[i] = GF_mul(d1, inv[aoff + o]);
    g[i] = GF_mul(d1, inv[boff + o]);
    h[i] = inv[coff + o];
  }
  const Fq b3 = anchors[boff];
  const Fq c5 = anchors[coff + 2u];
  f[1] = GF_mul(GF_mul(GF_mul(b3, c5), id1), id2);
  h[1] = GF_mul(GF_mul(b3, id1), id3);
  Fq inv_f2 = GF_mul(GF_mul(g[2], h[4]), d2);
  Fq inv_h2 = GF_mul(g[2], d3);
  g[0] = GF_mul(GF_mul(inv_f2, inv_h2), id4);
  return 0;
}

static void right_diagonal(Fq *out, const Fq *m, const Fq *diag)
{
  for (size_t r = 0; r < TRINE_n; r++)
    for (size_t c = 0; c < TRINE_n; c++)
      out[r * TRINE_n + c] = GF_mul(m[r * TRINE_n + c], diag[c]);
}

/* Exposes exactly the BuildUVW and DiagonalNormalize certificate. */
static int canonical_certificate(
    Fq *ta, Fq *tb, Fq *tc, Fq *canonical,
    const Fq *form, const Fq point[TRINE_n])
{
  const size_t form_elems = triform_element_count(TRINE_n);
  Fq u[TRINE_n * TRINE_n], v[TRINE_n * TRINE_n], w[TRINE_n * TRINE_n];
  Fq f[TRINE_n], g[TRINE_n], h[TRINE_n];
  Fq *transformed = malloc(form_elems * sizeof(*transformed));
  Fq *reference = malloc(form_elems * sizeof(*reference));
  int ret = -1;
  if (transformed == NULL || reference == NULL)
    goto done;
  if (canonical_build_uvw_vartime(u, v, w, form, point, TRINE_n) != 0)
    goto done;
  triform_action_pullback(transformed, form, u, v, w, TRINE_n);
  if (normalization_diagonals(f, g, h, transformed) != 0)
    goto done;
  right_diagonal(ta, u, f);
  right_diagonal(tb, v, g);
  right_diagonal(tc, w, h);
  triform_action_pullback(canonical, form, ta, tb, tc, TRINE_n);
  if (canonical_form_vartime(reference, form, point, TRINE_n) != 0 ||
      !fq_equal(canonical, reference, form_elems))
    goto done;
  ret = 0;
done:
  free(transformed);
  free(reference);
  return ret;
}

static int opening_at_round(
    Fq point[TRINE_n],
    const uint8_t sig[PDF_SIG_BYTES],
    const trine_challenge_t challenge[TRINE_r],
    size_t target,
    const Fq *base)
{
  Fq responses[TRINE_K * TRINE_n];
  uint8_t base_seeds[TRINE_BASE_SEED_BYTES], digest[TRINE_digest_bytes];
  size_t ri = 0, si = 0;
  if (decode_pdf_signature(responses, base_seeds, digest, sig) != 0)
    return -1;
  for (size_t i = 0; i <= target; i++)
  {
    if (challenge[i] == 0)
    {
      if (i == target)
      {
        memcpy(point, responses + ri * TRINE_n, TRINE_n * sizeof(*point));
        return 0;
      }
      ri++;
    }
    else if (challenge[i] == TRINE_BASE_FORM_INDEX)
    {
      if (i == target)
        return derive_pdf_commitment(
            point,
            (Fq[TRINE_n * TRINE_n * TRINE_n]){0},
            base,
            base_seeds + si * TRINE_round_seed_bytes,
            (uint32_t)i);
      si++;
    }
    else
      return -1;
  }
  return -1;
}

/*
 * Extract E with phi_0^(E_A,E_B,E_C)=phi_X.  Return -2 when the two
 * openings do not share a commitment, which is the independent-randomness
 * negative control rather than an extraction failure.
 */
static int extract_map(
    Fq *ea, Fq *eb, Fq *ec,
    size_t *round_out,
    const uint8_t sig1[PDF_SIG_BYTES],
    const trine_challenge_t c1[TRINE_r],
    const uint8_t sig2[PDF_SIG_BYTES],
    const trine_challenge_t c2[TRINE_r],
    const Fq *nonbase,
    const Fq *base)
{
  const size_t matrix_elems = (size_t)TRINE_n * TRINE_n;
  const size_t form_elems = triform_element_count(TRINE_n);
  Fq p1[TRINE_n], p2[TRINE_n];
  Fq *p_nonbase, *p_base;
  Fq t0a[matrix_elems], t0b[matrix_elems], t0c[matrix_elems];
  Fq t1a[matrix_elems], t1b[matrix_elems], t1c[matrix_elems];
  Fq inv1a[matrix_elems], inv1b[matrix_elems], inv1c[matrix_elems];
  Fq *cf0 = malloc(form_elems * sizeof(*cf0));
  Fq *cf1 = malloc(form_elems * sizeof(*cf1));
  int ret = -1;
  size_t round = TRINE_r;

  if (cf0 == NULL || cf1 == NULL)
    goto done;
  for (size_t i = 0; i < TRINE_r; i++)
    if (c1[i] != c2[i])
    {
      round = i;
      break;
    }
  if (round == TRINE_r)
    goto done;
  if (opening_at_round(p1, sig1, c1, round, base) != 0 ||
      opening_at_round(p2, sig2, c2, round, base) != 0)
    goto done;

  if (c1[round] == 0)
  {
    p_nonbase = p1;
    p_base = p2;
  }
  else
  {
    p_nonbase = p2;
    p_base = p1;
  }

  if (canonical_certificate(t0a, t0b, t0c, cf0, nonbase, p_nonbase) != 0 ||
      canonical_certificate(t1a, t1b, t1c, cf1, base, p_base) != 0)
    goto done;
  if (!fq_equal(cf0, cf1, form_elems))
  {
    ret = -2;
    goto done;
  }
  if (pmod_mat_inv_vartime(inv1a, t1a, TRINE_n) != 0 ||
      pmod_mat_inv_vartime(inv1b, t1b, TRINE_n) != 0 ||
      pmod_mat_inv_vartime(inv1c, t1c, TRINE_n) != 0)
    goto done;
  pmod_mat_mul(ea, t0a, inv1a, TRINE_n);
  pmod_mat_mul(eb, t0b, inv1b, TRINE_n);
  pmod_mat_mul(ec, t0c, inv1c, TRINE_n);
  *round_out = round;
  ret = 0;
done:
  free(cf0);
  free(cf1);
  return ret;
}

static int generate_key(
    uint8_t pk[TRINE_PK_BYTES],
    Fq *base, Fq *nonbase,
    Fq *actual_a_inv)
{
  uint8_t skseed[TRINE_secret_seed_bytes];
  uint8_t pubseed[TRINE_public_seed_bytes];
  Fq a[TRINE_n * TRINE_n], b[TRINE_n * TRINE_n], c[TRINE_n * TRINE_n];
  if (bytes_from_label(skseed, sizeof(skseed), "TRINE independent audit fixed key") != 0 ||
      trine_expand_public_seed(pubseed, skseed) != 0 ||
      trine_expand_base_form(base, pubseed, TRINE_n) != 0 ||
      trine_expand_secret_matrix_pair_vartime(
          a, actual_a_inv, skseed, TRINE_MATRIX_A, 0, TRINE_n) != 0 ||
      trine_expand_secret_matrix_pair_vartime(
          b, NULL, skseed, TRINE_MATRIX_B, 0, TRINE_n) != 0 ||
      trine_expand_secret_matrix_pair_vartime(
          c, NULL, skseed, TRINE_MATRIX_C, 0, TRINE_n) != 0)
    return -1;
  triform_action_pullback(nonbase, base, a, b, c, TRINE_n);
  return trine_codec_encode_public_key(pk, TRINE_PK_BYTES, pubseed, nonbase);
}

int main(void)
{
  const uint8_t m1[] = "TRINE reused commitment transcript A";
  const uint8_t m2[] = "TRINE reused commitment transcript B";
  const uint8_t mf[] = "TRINE witness-only fresh-message forgery";
  const uint8_t mw[] = "TRINE wrong message negative control";
  const size_t form_elems = triform_element_count(TRINE_n);
  const size_t matrix_elems = (size_t)TRINE_n * TRINE_n;
  uint8_t *pk = malloc(TRINE_PK_BYTES);
  Fq *base = malloc(form_elems * sizeof(*base));
  Fq *nonbase = malloc(form_elems * sizeof(*nonbase));
  Fq *check = malloc(form_elems * sizeof(*check));
  Fq actual_a_inv[matrix_elems];
  Fq ea[matrix_elems], eb[matrix_elems], ec[matrix_elems];
  Fq wrong[matrix_elems], corrupted[matrix_elems];
  commitment_batch *reuse = malloc(sizeof(*reuse));
  commitment_batch *independent = malloc(sizeof(*independent));
  commitment_batch *fresh = malloc(sizeof(*fresh));
  uint8_t s1[PDF_SIG_BYTES], s2[PDF_SIG_BYTES], si[PDF_SIG_BYTES];
  uint8_t sf[PDF_SIG_BYTES], sw[PDF_SIG_BYTES], sc[PDF_SIG_BYTES];
  trine_challenge_t c1[TRINE_r], c2[TRINE_r], ci[TRINE_r];
  trine_challenge_t cf[TRINE_r], cw[TRINE_r], cc[TRINE_r];
  size_t extraction_round = TRINE_r, dummy_round = TRINE_r;
  size_t equal_commitments = 0;
  double t0 = now_seconds();
  int ok = 1;

  if (pk == NULL || base == NULL || nonbase == NULL || check == NULL ||
      reuse == NULL || independent == NULL || fresh == NULL)
  {
    fprintf(stderr, "allocation failure\n");
    return 2;
  }

  if (generate_key(pk, base, nonbase, actual_a_inv) != 0)
  {
    fprintf(stderr, "key generation failure\n");
    return 2;
  }
  double t_key = now_seconds();
  if (build_batch(reuse, base, "TRINE controlled reused commitment batch") != 0)
  {
    fprintf(stderr, "reused batch failure\n");
    return 2;
  }
  double t_reuse = now_seconds();

  ok &= sign_from_batch(s1, c1, m1, sizeof(m1) - 1u, reuse, actual_a_inv) == 0;
  ok &= sign_from_batch(s2, c2, m2, sizeof(m2) - 1u, reuse, actual_a_inv) == 0;
  const int controlled_1_accept =
      verify_pdf_signature(s1, m1, sizeof(m1) - 1u, pk) == 0;
  const int controlled_2_accept =
      verify_pdf_signature(s2, m2, sizeof(m2) - 1u, pk) == 0;
  ok &= controlled_1_accept;
  ok &= controlled_2_accept;
  double t_pair = now_seconds();

  int extract_ret = extract_map(
      ea, eb, ec, &extraction_round, s1, c1, s2, c2, nonbase, base);
  triform_action_pullback(check, nonbase, ea, eb, ec, TRINE_n);
  const int full_relation = extract_ret == 0 && fq_equal(check, base, form_elems);
  ok &= full_relation;
  /* The remaining positive forgery path receives only the extracted map. */
  memset(actual_a_inv, 0, sizeof(actual_a_inv));
  double t_extract = now_seconds();

  if (build_batch(fresh, base, "TRINE witness-only fresh forgery batch") != 0)
  {
    fprintf(stderr, "fresh batch failure\n");
    return 2;
  }
  ok &= sign_from_batch(sf, cf, mf, sizeof(mf) - 1u, fresh, ea) == 0;
  const int forge_accept = verify_pdf_signature(sf, mf, sizeof(mf) - 1u, pk) == 0;
  ok &= forge_accept;
  double t_forge = now_seconds();

  /* Wrong orientation E_A^{-1}. */
  ok &= pmod_mat_inv_vartime(wrong, ea, TRINE_n) == 0;
  ok &= sign_from_batch(sw, cw, mf, sizeof(mf) - 1u, fresh, wrong) == 0;
  const int wrong_orientation_reject =
      verify_pdf_signature(sw, mf, sizeof(mf) - 1u, pk) != 0;
  ok &= wrong_orientation_reject;

  memcpy(corrupted, ea, sizeof(corrupted));
  corrupted[0] = GF_add(corrupted[0], 1);
  ok &= sign_from_batch(sc, cc, mf, sizeof(mf) - 1u, fresh, corrupted) == 0;
  const int corrupted_transform_reject =
      verify_pdf_signature(sc, mf, sizeof(mf) - 1u, pk) != 0;
  ok &= corrupted_transform_reject;
  const int wrong_message_reject =
      verify_pdf_signature(sf, mw, sizeof(mw) - 1u, pk) != 0;
  ok &= wrong_message_reject;
  double t_neg_forge = now_seconds();

  if (build_batch(independent, base, "TRINE independent commitment batch") != 0)
  {
    fprintf(stderr, "independent batch failure\n");
    return 2;
  }
  ok &= sign_from_batch(si, ci, m2, sizeof(m2) - 1u, independent, ea) == 0;
  const int independent_valid = verify_pdf_signature(
      si, m2, sizeof(m2) - 1u, pk) == 0;
  ok &= independent_valid;
  for (size_t i = 0; i < TRINE_r; i++)
    equal_commitments += hash_equal(
        reuse->encoded_psi + i * TRINE_TRIFORM_BYTES,
        independent->encoded_psi + i * TRINE_TRIFORM_BYTES,
        TRINE_TRIFORM_BYTES);
  const int independent_extract_ret = extract_map(
      wrong, corrupted, actual_a_inv, &dummy_round,
      s1, c1, si, ci, nonbase, base);
  const int independent_randomness_reject =
      equal_commitments == 0 && independent_extract_ret == -2;
  ok &= independent_randomness_reject;
  double t_end = now_seconds();

  size_t challenge_differences = 0;
  for (size_t i = 0; i < TRINE_r; i++)
    challenge_differences += c1[i] != c2[i];

  printf("schema=trine-special-soundness-independent-v1\n");
  printf("parameter_set=TRINE-128-Balanced\n");
  printf("parameters=n:%d,q:%d,r:%d,K:%d,X:%d\n",
         TRINE_n, TRINE_q, TRINE_r, TRINE_K, TRINE_X);
  printf("pdf_signature_bytes=%u\n", (unsigned)PDF_SIG_BYTES);
  printf("submitted_signature_bytes=%u\n", (unsigned)TRINE_SIG_BYTES);
  printf("source_only_salt_bytes=%u\n", (unsigned)TRINE_salt_bytes);
  printf("controlled_signature_1_accept=%s\n",
         controlled_1_accept ? "PASS" : "FAIL");
  printf("controlled_signature_2_accept=%s\n",
         controlled_2_accept ? "PASS" : "FAIL");
  printf("reused_commitments=%d/%d\n", TRINE_r, TRINE_r);
  printf("parsed_challenge_differences=%zu\n", challenge_differences);
  printf("extraction_round=%zu\n", extraction_round);
  printf("canonical_certificate_extraction=%s\n", extract_ret == 0 ? "PASS" : "FAIL");
  printf("full_equivalence_phi0_to_phiX=%s\n", full_relation ? "PASS" : "FAIL");
  printf("original_signing_matrix_erased_before_forgery=PASS\n");
  printf("witness_only_fresh_message_forgery=%s\n", forge_accept ? "PASS" : "FAIL");
  printf("negative_independent_signature_valid=%s\n", independent_valid ? "PASS" : "FAIL");
  printf("negative_independent_equal_commitments=%zu/%d\n", equal_commitments, TRINE_r);
  printf("negative_independent_extraction_rejected=%s\n",
         independent_randomness_reject ? "PASS" : "FAIL");
  printf("negative_wrong_orientation_rejected=%s\n",
         wrong_orientation_reject ? "PASS" : "FAIL");
  printf("negative_wrong_message_rejected=%s\n",
         wrong_message_reject ? "PASS" : "FAIL");
  printf("negative_corrupted_transform_rejected=%s\n",
         corrupted_transform_reject ? "PASS" : "FAIL");
  printf("timing_keygen_s=%.6f\n", t_key - t0);
  printf("timing_reused_batch_s=%.6f\n", t_reuse - t_key);
  printf("timing_pair_and_verification_s=%.6f\n", t_pair - t_reuse);
  printf("timing_extraction_s=%.6f\n", t_extract - t_pair);
  printf("timing_forge_s=%.6f\n", t_forge - t_extract);
  printf("timing_forgery_negatives_s=%.6f\n", t_neg_forge - t_forge);
  printf("timing_independent_control_s=%.6f\n", t_end - t_neg_forge);
  printf("timing_total_s=%.6f\n", t_end - t0);
  printf("overall=%s\n", ok ? "PASS" : "FAIL");

  free(pk);
  free(base);
  free(nonbase);
  free(check);
  free(reuse);
  free(independent);
  free(fresh);
  return ok ? 0 : 1;
}

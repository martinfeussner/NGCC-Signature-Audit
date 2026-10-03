#define _POSIX_C_SOURCE 200809L

/* Reuse the already validated PDF-aligned key/point helpers. */
#define main archived_special_soundness_main
#include "attack_support.c"
#undef main

#include <inttypes.h>
#include <math.h>

#define FP_COUNT 12
#define CHAIN_STEPS 4

static int partial_chain(
    Fq U[CHAIN_STEPS * TRINE_n],
    Fq V[CHAIN_STEPS * TRINE_n],
    Fq W[CHAIN_STEPS * TRINE_n],
    const Fq *form,
    const Fq point[TRINE_n])
{
  Fq current_v[TRINE_n], current_w[TRINE_n];
  Fq next_u[TRINE_n], next_v[TRINE_n];
  memcpy(U, point, TRINE_n * sizeof(*point));
  if (triform_phi_u_lker_corank1_vartime(current_v, form, point, TRINE_n) != 0)
    return -1;
  for (int step = 0; step < CHAIN_STEPS; step++)
  {
    memcpy(V + (size_t)step * TRINE_n, current_v,
           TRINE_n * sizeof(*current_v));
    if (triform_phi_v_rker_corank1_vartime(
            current_w, form, current_v, TRINE_n) != 0)
      return -1;
    memcpy(W + (size_t)step * TRINE_n, current_w,
           TRINE_n * sizeof(*current_w));
    if (step + 1 == CHAIN_STEPS)
      break;
    if (triform_matrix_at_w_lker_corank1_vartime(
            next_u, form, current_w, TRINE_n) != 0 ||
        triform_phi_u_lker_corank1_vartime(
            next_v, form, next_u, TRINE_n) != 0)
      return -1;
    memcpy(U + (size_t)(step + 1) * TRINE_n, next_u,
           TRINE_n * sizeof(*next_u));
    memcpy(current_v, next_v, sizeof(current_v));
  }
  return 0;
}

static Fq bilinear(const Fq *u, const Fq *matrix, const Fq *v)
{
  Fq mv[TRINE_n];
  Fq out = 0;
  pmod_mat_vec_mul(mv, matrix, v, TRINE_n);
  for (int i = 0; i < TRINE_n; i++)
    out = GF_add(out, GF_mul(u[i], mv[i]));
  return out;
}

/*
 * With i,j,k in {2,3}, return four two-dimensional ratios
 *
 *   T(u0,v1,w0) T(ui,vj,w0) / (T(ui,v1,w0) T(u0,vj,w0))
 *
 * and eight three-dimensional ratios
 *
 *   T(u0,v1,w0)^2 T(ui,vj,wk)
 *   -----------------------------------------------.
 *   T(ui,v1,w0) T(u0,vj,w0) T(u0,v1,wk)
 *
 * Every independent projective scale of the chain vectors cancels.  The
 * anchors in each denominator are exactly among the nonzero anchors required
 * by TRINE's full DiagonalNormalize procedure.
 */
static int partial_fingerprint(Fq out[FP_COUNT], const Fq *form, const Fq *point)
{
  Fq U[CHAIN_STEPS * TRINE_n];
  Fq V[CHAIN_STEPS * TRINE_n];
  Fq W[CHAIN_STEPS * TRINE_n];
  Fq matrix0[TRINE_n * TRINE_n];
  Fq matrixk[TRINE_n * TRINE_n];
  Fq denominators[FP_COUNT], inverses[FP_COUNT];
  Fq u0vj[2], uiv1[2], u0v1wk[2];
  if (partial_chain(U, V, W, form, point) != 0)
    return -1;
  triform_matrix_at_w(matrix0, form, W, TRINE_n);
  const Fq d1 = bilinear(U, matrix0, V + TRINE_n);
  if (d1 == 0)
    return -1;
  for (int jj = 0; jj < 2; jj++)
  {
    int j = jj + 2;
    u0vj[jj] = bilinear(U, matrix0, V + (size_t)j * TRINE_n);
    if (u0vj[jj] == 0)
      return -1;
  }
  for (int ii = 0; ii < 2; ii++)
  {
    int i = ii + 2;
    uiv1[ii] = bilinear(U + (size_t)i * TRINE_n, matrix0, V + TRINE_n);
    if (uiv1[ii] == 0)
      return -1;
  }
  for (int kk = 0; kk < 2; kk++)
  {
    int k = kk + 2;
    triform_matrix_at_w(matrixk, form, W + (size_t)k * TRINE_n, TRINE_n);
    u0v1wk[kk] = bilinear(U, matrixk, V + TRINE_n);
    if (u0v1wk[kk] == 0)
      return -1;
  }
  int pos = 0;
  for (int ii = 0; ii < 2; ii++)
    for (int jj = 0; jj < 2; jj++)
      denominators[pos++] = GF_mul(uiv1[ii], u0vj[jj]);
  for (int kk = 0; kk < 2; kk++)
    for (int ii = 0; ii < 2; ii++)
      for (int jj = 0; jj < 2; jj++)
        denominators[pos++] = GF_mul(
            GF_mul(uiv1[ii], u0vj[jj]), u0v1wk[kk]);
  if (GF_batch_inv(inverses, denominators, FP_COUNT) != 0)
    return -1;
  pos = 0;
  for (int ii = 0; ii < 2; ii++)
    for (int jj = 0; jj < 2; jj++)
    {
      int i = ii + 2, j = jj + 2;
      Fq numerator = GF_mul(
          d1,
          bilinear(U + (size_t)i * TRINE_n,
                   matrix0,
                   V + (size_t)j * TRINE_n));
      out[pos] = GF_mul(numerator, inverses[pos]);
      pos++;
    }
  const Fq d1_squared = GF_mul(d1, d1);
  for (int kk = 0; kk < 2; kk++)
  {
    int k = kk + 2;
    triform_matrix_at_w(matrixk, form, W + (size_t)k * TRINE_n, TRINE_n);
    for (int ii = 0; ii < 2; ii++)
      for (int jj = 0; jj < 2; jj++)
      {
        int i = ii + 2, j = jj + 2;
        Fq numerator = GF_mul(
            d1_squared,
            bilinear(U + (size_t)i * TRINE_n,
                     matrixk,
                     V + (size_t)j * TRINE_n));
        out[pos] = GF_mul(numerator, inverses[pos]);
        pos++;
      }
  }
  return 0;
}

static uint64_t fingerprint_hash(const Fq fp[FP_COUNT])
{
  /* Non-cryptographic test hash; exact tuples are always compared separately. */
  uint64_t h = UINT64_C(1469598103934665603);
  for (int i = 0; i < FP_COUNT; i++)
  {
    h ^= (uint8_t)fp[i]; h *= UINT64_C(1099511628211);
    h ^= (uint8_t)(fp[i] >> 8); h *= UINT64_C(1099511628211);
  }
  return h;
}

int main(int argc, char **argv)
{
  int trials = argc > 1 ? atoi(argv[1]) : 64;
  int bench_reps = argc > 2 ? atoi(argv[2]) : 100;
  const size_t fe = triform_element_count(TRINE_n);
  const size_t me = (size_t)TRINE_n * TRINE_n;
  uint8_t *pk = malloc(TRINE_PK_BYTES);
  Fq *base = malloc(fe * sizeof(*base));
  Fq *nonbase = malloc(fe * sizeof(*nonbase));
  Fq *psi = malloc(fe * sizeof(*psi));
  Fq *cf = malloc(fe * sizeof(*cf));
  Fq a_inv[me], a[TRINE_n], d[TRINE_n];
  Fq fp_base[FP_COUNT], fp_nonbase[FP_COUNT], fp_control[FP_COUNT];
  uint8_t seed[TRINE_round_seed_bytes];
  int equal = 0, controls_equal = 0, failures = 0;
  uint64_t xor_sink = 0;
  if (!pk || !base || !nonbase || !psi || !cf ||
      generate_key(pk, base, nonbase, a_inv) != 0)
    return 2;

  for (int t = 0; t < trials; t++)
  {
    char label[96];
    snprintf(label, sizeof(label), "TRINE partial invariant point %d", t);
    if (bytes_from_label(seed, sizeof(seed), label) != 0 ||
        derive_pdf_commitment(a, psi, base, seed, 0) != 0)
      return 2;
    pmod_mat_vec_mul(d, a_inv, a, TRINE_n);
    if (partial_fingerprint(fp_base, base, a) != 0 ||
        partial_fingerprint(fp_nonbase, nonbase, d) != 0)
    {
      failures++;
      continue;
    }
    equal += memcmp(fp_base, fp_nonbase, sizeof(fp_base)) == 0;

    snprintf(label, sizeof(label), "TRINE partial invariant control %d", t);
    if (bytes_from_label(seed, sizeof(seed), label) != 0 ||
        derive_pdf_commitment(a, psi, base, seed, 0) != 0 ||
        partial_fingerprint(fp_control, base, a) != 0)
      return 2;
    controls_equal += memcmp(fp_control, fp_nonbase, sizeof(fp_control)) == 0;
    xor_sink ^= fingerprint_hash(fp_base) ^ fingerprint_hash(fp_control);
  }

  /* Benchmark on one valid opening after cache warm-up. */
  if (bytes_from_label(seed, sizeof(seed), "TRINE invariant benchmark point") != 0 ||
      derive_pdf_commitment(a, psi, base, seed, 0) != 0 ||
      partial_fingerprint(fp_base, base, a) != 0 ||
      canonical_form_vartime(cf, base, a, TRINE_n) != 0)
    return 2;
  double t0 = now_seconds();
  for (int i = 0; i < bench_reps; i++)
  {
    if (partial_fingerprint(fp_base, base, a) != 0)
      return 2;
    xor_sink ^= fingerprint_hash(fp_base);
  }
  double t1 = now_seconds();
  for (int i = 0; i < bench_reps; i++)
  {
    if (canonical_form_vartime(cf, base, a, TRINE_n) != 0)
      return 2;
    xor_sink ^= cf[(size_t)i % fe];
  }
  double t2 = now_seconds();

  printf("parameter_set=%s\n", TRINE_PARAMETER_SET_NAME);
  printf("n=%d q=%d trials=%d failures=%d\n", TRINE_n, TRINE_q, trials, failures);
  printf("planted_equivariance_equal=%d/%d\n", equal, trials - failures);
  printf("independent_control_equal=%d/%d\n", controls_equal, trials - failures);
  printf("fingerprint_values=%d nominal_bits=%.6f\n",
         FP_COUNT, FP_COUNT * (log((double)TRINE_q) / log(2.0)));
  printf("partial_seconds_total=%.9f per_call=%.9g\n",
         t1 - t0, (t1 - t0) / bench_reps);
  printf("full_cf_seconds_total=%.9f per_call=%.9g\n",
         t2 - t1, (t2 - t1) / bench_reps);
  printf("speedup=%.6f sink=%" PRIu64 "\n",
         (t2 - t1) / (t1 - t0), xor_sink);
  free(pk); free(base); free(nonbase); free(psi); free(cf);
  return (failures == 0 && equal == trials && controls_equal == 0) ? 0 : 1;
}

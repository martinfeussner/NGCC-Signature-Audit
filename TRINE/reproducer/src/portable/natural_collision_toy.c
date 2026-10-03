#define _POSIX_C_SOURCE 200809L
#define main archived_special_soundness_main
#include "attack_support.c"
#undef main

#define TOY_SEED_BITS 8
#define MAX_BATCHES 12

static int build_natural_toy_batch(
    commitment_batch *batch, const Fq *base, unsigned batch_index)
{
  const size_t fe = triform_element_count(TRINE_n);
  Fq *psi = malloc(fe * sizeof(*psi));
  if (psi == NULL)
    return -1;
  for (uint32_t round = 0; round < (uint32_t)TRINE_r; round++)
  {
    char label[128];
    uint8_t raw[TRINE_round_seed_bytes];
    snprintf(label, sizeof(label),
             "TRINE natural independent toy seed batch=%u round=%u",
             batch_index, round);
    if (bytes_from_label(raw, sizeof(raw), label) != 0)
    {
      free(psi); return -1;
    }
    /* Reduced-entropy profile: a fresh uniform byte, never copied/reset. */
    uint8_t *seed = batch->seeds + (size_t)round * TRINE_round_seed_bytes;
    memset(seed, 0, TRINE_round_seed_bytes);
    seed[0] = raw[0];
    Fq *a = batch->a + (size_t)round * TRINE_n;
    uint8_t *encoded = batch->encoded_psi + (size_t)round * TRINE_TRIFORM_BYTES;
    if (derive_spec_commitment(a, psi, base, seed, round) != 0 ||
        trine_codec_encode_triform(encoded, TRINE_TRIFORM_BYTES,
                                  psi, TRINE_n) != 0)
    {
      free(psi); return -1;
    }
  }
  free(psi);
  return 0;
}

static int extract_map_at(
    Fq *ea, Fq *eb, Fq *ec,
    size_t round,
    const uint8_t sig1[SPEC_SIG_BYTES], const trine_challenge_t c1[TRINE_r],
    const uint8_t sig2[SPEC_SIG_BYTES], const trine_challenge_t c2[TRINE_r],
    const Fq *nonbase, const Fq *base)
{
  const size_t me = (size_t)TRINE_n * TRINE_n;
  const size_t fe = triform_element_count(TRINE_n);
  Fq p1[TRINE_n], p2[TRINE_n], *p_nonbase, *p_base;
  Fq t0a[me], t0b[me], t0c[me], t1a[me], t1b[me], t1c[me];
  Fq inv1a[me], inv1b[me], inv1c[me];
  Fq *cf0 = malloc(fe * sizeof(*cf0));
  Fq *cf1 = malloc(fe * sizeof(*cf1));
  int ret = -1;
  if (!cf0 || !cf1 || round >= TRINE_r || c1[round] == c2[round])
    goto done;
  if (opening_at_round(p1, sig1, c1, round, base) != 0 ||
      opening_at_round(p2, sig2, c2, round, base) != 0)
    goto done;
  if (c1[round] == 0 && c2[round] == TRINE_BASE_FORM_INDEX)
    p_nonbase = p1, p_base = p2;
  else if (c2[round] == 0 && c1[round] == TRINE_BASE_FORM_INDEX)
    p_nonbase = p2, p_base = p1;
  else
    goto done;
  if (canonical_certificate(t0a,t0b,t0c,cf0,nonbase,p_nonbase) != 0 ||
      canonical_certificate(t1a,t1b,t1c,cf1,base,p_base) != 0 ||
      !fq_equal(cf0,cf1,fe) ||
      pmod_mat_inv_vartime(inv1a,t1a,TRINE_n) != 0 ||
      pmod_mat_inv_vartime(inv1b,t1b,TRINE_n) != 0 ||
      pmod_mat_inv_vartime(inv1c,t1c,TRINE_n) != 0)
    goto done;
  pmod_mat_mul(ea,t0a,inv1a,TRINE_n);
  pmod_mat_mul(eb,t0b,inv1b,TRINE_n);
  pmod_mat_mul(ec,t0c,inv1c,TRINE_n);
  ret = 0;
done:
  free(cf0); free(cf1); return ret;
}

int main(void)
{
  const size_t fe = triform_element_count(TRINE_n);
  const size_t me = (size_t)TRINE_n * TRINE_n;
  uint8_t *pk = malloc(TRINE_PK_BYTES);
  Fq *base = malloc(fe * sizeof(*base));
  Fq *nonbase = malloc(fe * sizeof(*nonbase));
  Fq *check = malloc(fe * sizeof(*check));
  commitment_batch **batches = calloc(MAX_BATCHES, sizeof(*batches));
  uint8_t (*sigs)[SPEC_SIG_BYTES] = calloc(MAX_BATCHES, SPEC_SIG_BYTES);
  trine_challenge_t (*chals)[TRINE_r] = calloc(MAX_BATCHES, sizeof(*chals));
  Fq actual_a_inv[me], ea[me], eb[me], ec[me], corrupted[me];
  int found = 0, left = -1, right = -1, found_round = -1;
  int generated = 0, all_valid = 1;
  double start = now_seconds();
  if (!pk || !base || !nonbase || !check || !batches || !sigs || !chals ||
      generate_key(pk,base,nonbase,actual_a_inv) != 0)
    return 2;

  for (int b = 0; b < MAX_BATCHES && !found; b++)
  {
    uint8_t message[64];
    int mlen = snprintf((char *)message, sizeof(message),
                        "TRINE natural-collision toy message %d", b);
    batches[b] = malloc(sizeof(*batches[b]));
    if (!batches[b] || build_natural_toy_batch(batches[b],base,(unsigned)b) != 0 ||
        sign_from_batch(sigs[b],chals[b],message,(size_t)mlen,
                        batches[b],actual_a_inv) != 0)
      return 2;
    all_valid &= verify_spec_signature(sigs[b],message,(size_t)mlen,pk) == 0;
    generated++;
    for (int aidx = 0; aidx < b && !found; aidx++)
      for (int round = 0; round < TRINE_r; round++)
        if (chals[aidx][round] != chals[b][round] &&
            memcmp(batches[aidx]->seeds + (size_t)round * TRINE_round_seed_bytes,
                   batches[b]->seeds + (size_t)round * TRINE_round_seed_bytes,
                   TRINE_round_seed_bytes) == 0 &&
            memcmp(batches[aidx]->encoded_psi + (size_t)round * TRINE_TRIFORM_BYTES,
                   batches[b]->encoded_psi + (size_t)round * TRINE_TRIFORM_BYTES,
                   TRINE_TRIFORM_BYTES) == 0)
        {
          found=1; left=aidx; right=b; found_round=round; break;
        }
  }
  if (!found || !all_valid ||
      extract_map_at(ea,eb,ec,(size_t)found_round,
                     sigs[left],chals[left],sigs[right],chals[right],
                     nonbase,base) != 0)
    return 1;
  triform_action_pullback(check,nonbase,ea,eb,ec,TRINE_n);
  int full_relation = fq_equal(check,base,fe);
  memset(actual_a_inv,0,sizeof(actual_a_inv));

  commitment_batch *fresh = malloc(sizeof(*fresh));
  uint8_t forged[SPEC_SIG_BYTES];
  trine_challenge_t forge_chal[TRINE_r];
  const uint8_t fresh_message[] = "TRINE natural-collision toy fresh forgery";
  const uint8_t wrong_message[] = "TRINE natural-collision toy wrong message";
  if (!fresh || build_batch(fresh,base,"TRINE natural toy fresh full-entropy batch") != 0 ||
      sign_from_batch(forged,forge_chal,fresh_message,sizeof(fresh_message)-1,
                      fresh,ea) != 0)
    return 2;
  int fresh_accept = verify_spec_signature(
      forged,fresh_message,sizeof(fresh_message)-1,pk) == 0;
  int wrong_message_reject = verify_spec_signature(
      forged,wrong_message,sizeof(wrong_message)-1,pk) != 0;
  memcpy(corrupted,ea,sizeof(corrupted));
  corrupted[0] = GF_add(corrupted[0],1);
  uint8_t bad[SPEC_SIG_BYTES]; trine_challenge_t bad_chal[TRINE_r];
  int bad_built = sign_from_batch(
      bad,bad_chal,fresh_message,sizeof(fresh_message)-1,fresh,corrupted) == 0;
  int corrupted_reject = bad_built && verify_spec_signature(
      bad,fresh_message,sizeof(fresh_message)-1,pk) != 0;

  printf("schema=trine-natural-collision-toy-v1\n");
  printf("parameter_shape=Balanced-I n=%d q=%d r=%d K=%d X=%d\n",
         TRINE_n,TRINE_q,TRINE_r,TRINE_K,TRINE_X);
  printf("toy_seed_bits=%d sampling=independent_fresh_uniform\n",TOY_SEED_BITS);
  printf("generated_signatures=%d all_signatures_valid=%s\n",
         generated, all_valid?"PASS":"FAIL");
  printf("natural_seed_collision=PASS left=%d right=%d round=%d labels=%u,%u\n",
         left,right,found_round,(unsigned)chals[left][found_round],
         (unsigned)chals[right][found_round]);
  printf("commitment_equality=PASS\n");
  printf("extracted_full_equivalence=%s\n",full_relation?"PASS":"FAIL");
  printf("original_signing_matrix_erased_before_forgery=PASS\n");
  printf("witness_only_fresh_message_forgery=%s\n",fresh_accept?"PASS":"FAIL");
  printf("negative_wrong_message_rejected=%s\n",wrong_message_reject?"PASS":"FAIL");
  printf("negative_corrupted_map_rejected=%s\n",corrupted_reject?"PASS":"FAIL");
  printf("elapsed_seconds=%.6f\n",now_seconds()-start);
  int ok = full_relation && fresh_accept && wrong_message_reject && corrupted_reject;
  printf("overall=%s\n",ok?"PASS":"FAIL");
  for(int i=0;i<generated;i++) free(batches[i]);
  free(fresh); free(pk); free(base); free(nonbase); free(check);
  free(batches); free(sigs); free(chals);
  return ok?0:1;
}

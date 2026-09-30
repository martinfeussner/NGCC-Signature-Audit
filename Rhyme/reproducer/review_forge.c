#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "encoding.h"
#include "packing.h"
#include "poly.h"
#include "reduce.h"
#include "rhyme_xof.h"
#include "sampler.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static void negacyclic(poly *out, const int16_t s[N], const poly *c) {
    int64_t acc[N] = {0};
    for (int i = 0; i < N; i++) for (int j = 0; j < N; j++) {
        int t = i + j; int64_t v = (int64_t)s[i] * c->coeffs[j];
        if (t < N) acc[t] += v; else acc[t - N] -= v;
    }
    for (int i = 0; i < N; i++) out->coeffs[i] = (int32_t)acc[i];
}

static void expand_A_local(poly A[K][M_SGEN], const uint8_t seedA[SEEDBYTES]) {
    for (int i = 0; i < K; i++) for (int j = 0; j < M_SGEN; j++)
        poly_uniform_ntt(&A[i][j], seedA, (uint16_t)((i << 8) | j));
}

static int public_relation(const uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                           const int16_t s[D_REST][N]) {
    uint8_t seedA[SEEDBYTES]; poly b[K], A[K][M_SGEN], sh[M_SGEN];
    unpack_pk(seedA, b, pk); expand_A_local(A, seedA);
    for (int j = 0; j < M_SGEN; j++) {
        for (int t = 0; t < N; t++) sh[j].coeffs[t] = s[j][t];
        poly_ntt(&sh[j]);
    }
    for (int i = 0; i < K; i++) {
        poly acc; poly_zero(&acc);
        for (int j = 0; j < M_SGEN; j++) poly_basemul_acc(&acc, &A[i][j], &sh[j]);
        poly_invntt_tomont(&acc);
        for (int t = 0; t < N; t++) acc.coeffs[t] += s[M_SGEN + i][t];
        poly_freeze(&acc);
        for (int t = 0; t < N; t++) if (acc.coeffs[t] != b[i].coeffs[t]) return -1;
    }
    return 0;
}

static int forge(uint8_t sig[CRYPTO_BYTES], size_t *siglen,
                 const uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t *msg,
                 size_t mlen, const int16_t s[D_REST][N], uint64_t *sq_out) {
    uint8_t mu[CRHBYTES], ct[CTILDEBYTES], wbuf[W_PACKEDBYTES];
    poly w[K], c, z1, z[D_REST]; keccak_state ks;
    for (int i = 0; i < K; i++) poly_zero(&w[i]);
    pack_w(wbuf, w);
    rhyme_shake256_init(&ks); rhyme_shake256_absorb(&ks, pk, CRYPTO_PUBLICKEYBYTES);
    rhyme_shake256_absorb(&ks, msg, mlen); rhyme_shake256_finalize(&ks);
    rhyme_shake256_squeeze(mu, CRHBYTES, &ks);
    rhyme_shake256_init(&ks); rhyme_shake256_absorb(&ks, wbuf, W_PACKEDBYTES);
    rhyme_shake256_absorb(&ks, mu, CRHBYTES); rhyme_shake256_finalize(&ks);
    rhyme_shake256_squeeze(ct, CTILDEBYTES, &ks); SampleChallenge(&c, ct);
    z1 = c;
    for (int r = 0; r < D_REST; r++) negacyclic(&z[r], s[r], &c);
    uint64_t sq = 0; poly_sqnorm_acc(&sq, &z1);
    for (int r = 0; r < D_REST; r++) poly_sqnorm_acc(&sq, &z[r]);
    *sq_out = sq;
    return pack_sig(sig, siglen, ct, &z1, z);
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char path[512]; uint8_t pk[CRYPTO_PUBLICKEYBYTES]; int16_t s[D_REST][N], truth[D_REST][N];
    snprintf(path, sizeof path, "%s.pk", argv[1]); FILE *f = fopen(path, "rb");
    if (!f || fread(pk, 1, sizeof pk, f) != sizeof pk) return 2;
    fclose(f);
    snprintf(path, sizeof path, "%s.recovered", argv[1]); f = fopen(path, "rb");
    if (!f || fread(s, 1, sizeof s, f) != sizeof s) return 2;
    fclose(f);
    snprintf(path, sizeof path, "%s.secret", argv[1]); f = fopen(path, "rb");
    int have_truth = f && fread(truth, 1, sizeof truth, f) == sizeof truth;
    if (f) fclose(f);
    size_t exact = 0;
    if (have_truth) for (int r = 0; r < D_REST; r++) for (int i = 0; i < N; i++)
        exact += s[r][i] == truth[r][i];
    int relation = public_relation(pk, s);

    const uint8_t msg[] = "hostile-review fresh forgery";
    const uint8_t wrong[] = "hostile-review wrong message";
    uint8_t sig[CRYPTO_BYTES], bad[CRYPTO_BYTES]; size_t siglen = 0, badlen = 0; uint64_t sq, badsq;
    int pack = forge(sig, &siglen, pk, msg, sizeof msg - 1, s, &sq);
    int valid = pack ? -99 : crypto_sign_verify(sig, siglen, msg, sizeof msg - 1, pk);
    if (!pack) {
        snprintf(path, sizeof path, "%s.forgery", argv[1]);
        f = fopen(path, "wb");
        if (!f || fwrite(sig, 1, siglen, f) != siglen || fclose(f)) return 3;
        snprintf(path, sizeof path, "%s.forgery-message", argv[1]);
        f = fopen(path, "wb");
        if (!f || fwrite(msg, 1, sizeof msg - 1, f) != sizeof msg - 1 || fclose(f)) return 3;
    }
    int wrong_msg = pack ? -99 : crypto_sign_verify(sig, siglen, wrong, sizeof wrong - 1, pk);
    int16_t pert[D_REST][N]; memcpy(pert, s, sizeof pert); pert[0][0]++;
    int badpack = forge(bad, &badlen, pk, msg, sizeof msg - 1, pert, &badsq);
    int pert_valid = badpack ? -99 : crypto_sign_verify(bad, badlen, msg, sizeof msg - 1, pk);

    unsigned char nonce[64]; for (unsigned i = 0; i < sizeof nonce; i++) nonce[i] = (uint8_t)(11*i+5);
    init_random_number(&drng_algorithm, nonce, sizeof nonce);
    uint8_t *pk2 = calloc(CRYPTO_PUBLICKEYBYTES, 1), *sk2 = calloc(CRYPTO_SECRETKEYBYTES, 1);
    int keyrc = (!pk2 || !sk2) ? -1 : crypto_sign_keypair(pk2, sk2);
    int wrong_key = keyrc ? -99 : crypto_sign_verify(sig, siglen, msg, sizeof msg - 1, pk2);
    if (have_truth) printf("exact=%zu/%d ", exact, D_REST*N);
    else printf("exact=not-read ");
    printf("public_relation=%d pack=%d valid=%d siglen=%zu norm_sq=%" PRIu64 "\n",
           relation, pack, valid, siglen, sq);
    printf("wrong_message=%d perturbed_tail=%d wrong_key=%d\n", wrong_msg, pert_valid, wrong_key);
    free(sk2); free(pk2);
    return (!have_truth || exact == D_REST*N) && relation == 0 && pack == 0 && valid == 0 &&
           wrong_msg != 0 && pert_valid != 0 && wrong_key != 0 ? 0 : 4;
}

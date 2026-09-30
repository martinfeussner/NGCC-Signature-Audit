#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "packing.h"
#include "sampler.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
    uint64_t target = argc > 1 ? strtoull(argv[1], NULL, 10) : 50000;
    const char *prefix = argc > 2 ? argv[2] : "review";
    uint64_t key_tag = argc > 3 ? strtoull(argv[3], NULL, 0) : UINT64_C(0x9e3779b97f4a7c15);
    uint64_t max_calls = argc > 4 ? strtoull(argv[4], NULL, 10) : target * 10;
    unsigned char nonce[64];
    for (unsigned i = 0; i < sizeof nonce; i++)
        nonce[i] = (unsigned char)(0xA7u + 29u * i + (key_tag >> (8 * (i & 7))));
    init_random_number(&drng_algorithm, nonce, sizeof nonce);

    uint8_t *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    uint8_t *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    uint8_t *sig = calloc(CRYPTO_BYTES, 1);
    if (!pk || !sk || !sig || crypto_sign_keypair(pk, sk) != 0) return 2;

    char path[512];
    snprintf(path, sizeof path, "%s.records", prefix);
    FILE *records = fopen(path, "wb"); if (!records) return 3;
    snprintf(path, sizeof path, "%s.pk", prefix);
    FILE *f = fopen(path, "wb"); if (!f) return 3;
    fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, f); fclose(f);

    /* Stored only for reviewer scoring; the estimator never reads this file. */
    secret_basis B; uint8_t pk2[CRYPTO_PUBLICKEYBYTES], key[SEEDBYTES];
    unpack_sk(pk2, &B, key, sk);
    if (memcmp(pk, pk2, sizeof pk2)) return 4;
    snprintf(path, sizeof path, "%s.secret", prefix);
    f = fopen(path, "wb"); if (!f) return 3;
    for (int r = 0; r < D_REST; r++) for (int j = 0; j < N; j++) {
        int16_t x = (int16_t)B.row_small[r][0].coeffs[j];
        fwrite(&x, sizeof x, 1, f);
    }
    fclose(f);

    uint64_t accepted = 0, sign_fail = 0, verify_fail = 0, unpack_fail = 0;
    for (uint64_t call = 0; call < max_calls && accepted < target; call++) {
        uint8_t msg[40] = "hostile review independent message";
        for (unsigned j = 0; j < 8; j++) msg[32 + j] = (uint8_t)(call >> (8 * j));
        size_t siglen = 0;
        if (crypto_sign_signature(sig, &siglen, msg, sizeof msg, sk) != 0) {
            sign_fail++; continue;
        }
        if (crypto_sign_verify(sig, siglen, msg, sizeof msg, pk) != 0) {
            verify_fail++; continue;
        }
        uint8_t ctilde[CTILDEBYTES]; poly z1, z[D_REST], c;
        if (unpack_sig(ctilde, &z1, z, sig, siglen) != 0) {
            unpack_fail++; continue;
        }
        SampleChallenge(&c, ctilde);
        for (int j = 0; j < N; j++) {
            uint8_t bit = (uint8_t)(c.coeffs[j] & 1);
            fwrite(&bit, 1, 1, records);
        }
        for (int r = 0; r < D_REST; r++) for (int j = 0; j < N; j++) {
            int16_t x = (int16_t)z[r].coeffs[j];
            fwrite(&x, sizeof x, 1, records);
        }
        accepted++;
        if (!(accepted % 10000))
            fprintf(stderr, "accepted=%" PRIu64 " calls=%" PRIu64 "\n", accepted, call + 1);
    }
    fclose(records);
    printf("target=%" PRIu64 " accepted=%" PRIu64 " sign_fail=%" PRIu64
           " verify_fail=%" PRIu64 " unpack_fail=%" PRIu64 "\n",
           target, accepted, sign_fail, verify_fail, unpack_fail);
    free(sig); free(sk); free(pk);
    return accepted == target && !verify_fail && !unpack_fail ? 0 : 5;
}

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "packing.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static void make_message(uint8_t msg[40], uint64_t call) {
    static const uint8_t base[40] = "hostile review independent message";
    memcpy(msg, base, 40);
    for (unsigned j = 0; j < 8; j++)
        msg[32 + j] = (uint8_t)(call >> (8 * j));
}

int main(int argc, char **argv) {
    uint64_t target = argc > 1 ? strtoull(argv[1], NULL, 10) : 50000;
    const char *prefix = argc > 2 ? argv[2] : "oracle";
    uint64_t key_tag = argc > 3 ? strtoull(argv[3], NULL, 0)
                                : UINT64_C(0x6a09e667f3bcc909);
    uint64_t max_calls = argc > 4 ? strtoull(argv[4], NULL, 10) : target * 10;

    unsigned char nonce[64];
    for (unsigned i = 0; i < sizeof nonce; i++)
        nonce[i] = (unsigned char)(0xA7u + 29u * i
                    + (key_tag >> (8 * (i & 7))));
    init_random_number(&drng_algorithm, nonce, sizeof nonce);

    uint8_t *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    uint8_t *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    uint8_t *sig = calloc(CRYPTO_BYTES, 1);
    if (!pk || !sk || !sig || crypto_sign_keypair(pk, sk) != 0) return 2;

    char path[512];
    snprintf(path, sizeof path, "%s.oracle", prefix);
    FILE *oracle = fopen(path, "wb");
    if (!oracle) return 3;
    snprintf(path, sizeof path, "%s.pk", prefix);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, f) != CRYPTO_PUBLICKEYBYTES
            || fclose(f)) return 3;

    /* Retained only for after-the-fact scoring; recovery never reads this file. */
    secret_basis B;
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES], key[SEEDBYTES];
    unpack_sk(pk2, &B, key, sk);
    if (memcmp(pk, pk2, sizeof pk2)) return 4;
    snprintf(path, sizeof path, "%s.secret", prefix);
    f = fopen(path, "wb");
    if (!f) return 3;
    for (int r = 0; r < D_REST; r++) for (int j = 0; j < N; j++) {
        int16_t x = (int16_t)B.row_small[r][0].coeffs[j];
        if (fwrite(&x, sizeof x, 1, f) != 1) return 3;
    }
    if (fclose(f)) return 3;

    uint64_t emitted = 0, sign_fail = 0, local_verify_fail = 0;
    rhyme_pack_failures_total = 0;
    rhyme_z1_unencodable_failures = 0;
    for (uint64_t call = 0; call < max_calls && emitted < target; call++) {
        uint8_t msg[40];
        make_message(msg, call);
        size_t siglen = 0;
        if (crypto_sign_signature(sig, &siglen, msg, sizeof msg, sk) != 0) {
            sign_fail++;
            continue;
        }
        if (crypto_sign_verify(sig, siglen, msg, sizeof msg, pk) != 0) {
            local_verify_fail++;
            continue;
        }
        if (siglen > UINT16_MAX) return 4;
        uint16_t slen = (uint16_t)siglen;
        if (fwrite(&call, sizeof call, 1, oracle) != 1
                || fwrite(&slen, sizeof slen, 1, oracle) != 1
                || fwrite(sig, 1, siglen, oracle) != siglen) return 3;
        emitted++;
        if (!(emitted % 10000))
            fprintf(stderr, "emitted=%" PRIu64 " calls=%" PRIu64 "\n",
                    emitted, call + 1);
    }
    if (fclose(oracle)) return 3;
    printf("target=%" PRIu64 " emitted=%" PRIu64 " sign_fail=%" PRIu64
           " local_verify_fail=%" PRIu64 " pack_failures=%" PRIu64
           " z1_unencodable=%" PRIu64 " other_pack_failures=%" PRIu64 "\n",
           target, emitted, sign_fail, local_verify_fail,
           rhyme_pack_failures_total, rhyme_z1_unencodable_failures,
           rhyme_pack_failures_total - rhyme_z1_unencodable_failures);
    free(sig); free(sk); free(pk);
    return emitted == target && !local_verify_fail ? 0 : 5;
}

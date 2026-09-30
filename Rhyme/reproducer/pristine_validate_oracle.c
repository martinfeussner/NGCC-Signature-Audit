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

static void make_message(uint8_t msg[40], uint64_t call) {
    static const uint8_t base[40] = "hostile review independent message";
    memcpy(msg, base, 40);
    for (unsigned j = 0; j < 8; j++)
        msg[32 + j] = (uint8_t)(call >> (8 * j));
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) return 1;
    const char *prefix = argv[1];
    uint64_t expected = argc == 3 ? strtoull(argv[2], NULL, 10) : 50000;
    char path[512];

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    snprintf(path, sizeof path, "%s.pk", prefix);
    FILE *f = fopen(path, "rb");
    if (!f || fread(pk, 1, sizeof pk, f) != sizeof pk || fclose(f)) return 2;
    snprintf(path, sizeof path, "%s.oracle", prefix);
    FILE *oracle = fopen(path, "rb");
    if (!oracle) return 2;
    snprintf(path, sizeof path, "%s.records", prefix);
    FILE *records = fopen(path, "wb");
    if (!records) return 2;

    uint8_t *sig = calloc(CRYPTO_BYTES, 1);
    if (!sig) return 2;
    uint64_t total = 0, accepted = 0, verify_fail = 0, unpack_fail = 0;
    for (;;) {
        uint64_t call;
        uint16_t siglen;
        size_t got = fread(&call, sizeof call, 1, oracle);
        if (got == 0 && feof(oracle)) break;
        if (got != 1 || fread(&siglen, sizeof siglen, 1, oracle) != 1
                || siglen > CRYPTO_BYTES
                || fread(sig, 1, siglen, oracle) != siglen) return 3;
        total++;
        uint8_t msg[40];
        make_message(msg, call);
        if (crypto_sign_verify(sig, siglen, msg, sizeof msg, pk) != 0) {
            verify_fail++;
            continue;
        }
        uint8_t ctilde[CTILDEBYTES];
        poly z1, z[D_REST], c;
        if (unpack_sig(ctilde, &z1, z, sig, siglen) != 0) {
            unpack_fail++;
            continue;
        }
        SampleChallenge(&c, ctilde);
        for (int j = 0; j < N; j++) {
            uint8_t bit = (uint8_t)(c.coeffs[j] & 1);
            if (fwrite(&bit, 1, 1, records) != 1) return 3;
        }
        for (int r = 0; r < D_REST; r++) for (int j = 0; j < N; j++) {
            int16_t x = (int16_t)z[r].coeffs[j];
            if (fwrite(&x, sizeof x, 1, records) != 1) return 3;
        }
        accepted++;
    }
    if (fclose(records) || fclose(oracle)) return 3;
    free(sig);
    printf("oracle=%" PRIu64 " pristine_accept=%" PRIu64
           " verify_fail=%" PRIu64 " unpack_fail=%" PRIu64 "\n",
           total, accepted, verify_fail, unpack_fail);
    return total == expected && accepted == expected
           && !verify_fail && !unpack_fail ? 0 : 5;
}

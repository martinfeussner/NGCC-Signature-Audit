#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

int main(void) {
    static const unsigned char msg[] = "TRINE full-entropy PDF-alignment conformance";
    unsigned char *pk = calloc(CRYPTO_PUBLICKEYBYTES, 1);
    unsigned char *sk = calloc(CRYPTO_SECRETKEYBYTES, 1);
    unsigned char *sm = calloc(CRYPTO_BYTES + sizeof msg, 1);
    unsigned char *opened = calloc(sizeof msg, 1);
    unsigned long long smlen = 0, opened_len = 0;
    if (!pk || !sk || !sm || !opened) return 10;
    if (crypto_sign_keypair(pk, sk) != 0) return 11;
    if (crypto_sign(sm, &smlen, msg, sizeof msg - 1, sk) != 0) return 12;
    if (smlen != (unsigned long long)CRYPTO_BYTES + sizeof msg - 1) return 13;
    if (crypto_sign_verify(sm, CRYPTO_BYTES, msg, sizeof msg - 1, pk) != 0) return 14;
    if (crypto_sign_open(opened, &opened_len, sm, smlen, pk) != 0) return 15;
    if (opened_len != sizeof msg - 1 || memcmp(opened, msg, opened_len) != 0) return 16;
    unsigned char wrong[sizeof msg];
    memcpy(wrong, msg, sizeof msg); wrong[0] ^= 1;
    if (crypto_sign_verify(sm, CRYPTO_BYTES, wrong, sizeof msg - 1, pk) == 0) return 17;
    printf("profile=%s\n", CRYPTO_ALGNAME);
    printf("lambda_bits=%d\n", TRINE_lambda);
    printf("round_seed_bytes=%d\n", TRINE_round_seed_bytes);
    printf("signature_bytes=%d\n", CRYPTO_BYTES);
    printf("verify=PASS\nopen=PASS\nchanged_message=REJECT\n");
    free(opened); free(sm); free(sk); free(pk);
    return 0;
}

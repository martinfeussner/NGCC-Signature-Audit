#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "drng.h"
#include "hash.h"
#include "params.h"
#include "wots.h"

DRNG_ctx drng_algorithm;

static int all_true = 1;

static void result(const char *name, int value)
{
    static int first = 1;
    printf("%s%s\":%s", first ? "{\n  \"" : ",\n  \"",
           name, value ? "true" : "false");
    first = 0;
    all_true &= value;
}

int main(void)
{
    static const unsigned char nonce[64] = {
        0x43,0x45,0x44,0x52,0x55,0x53,0x2d,0x61,
        0x6c,0x70,0x68,0x61,0x2d,0x66,0x72,0x65,
        0x73,0x68,0x32,0x2d,0x6e,0x61,0x74,0x69,
        0x76,0x65,0x2d,0x63,0x68,0x65,0x63,0x6b,
        0x43,0x45,0x44,0x52,0x55,0x53,0x2d,0x61,
        0x6c,0x70,0x68,0x61,0x2d,0x66,0x72,0x65,
        0x73,0x68,0x32,0x2d,0x6e,0x61,0x74,0x69,
        0x76,0x65,0x2d,0x63,0x68,0x65,0x63,0x6b
    };
    const unsigned char msg[] = "spec-conformant CEDRUS-alpha native check";
    const size_t mlen = sizeof(msg) - 1;
    unsigned char changed[sizeof(msg) - 1];
    unsigned char *pk = calloc(SPX_PK_BYTES, 1);
    unsigned char *sk = calloc(SPX_SK_BYTES, 1);
    unsigned char *pk2 = calloc(SPX_PK_BYTES, 1);
    unsigned char *sk2 = calloc(SPX_SK_BYTES, 1);
    unsigned char *sig = calloc(SPX_BYTES, 1);
    unsigned char *sig2 = calloc(SPX_BYTES, 1);
    unsigned char *tmp = calloc(SPX_BYTES, 1);
    size_t siglen = 0, siglen2 = 0;
    uint32_t a0[8] = {0}, a256[8] = {0};
    unsigned int z[SPX_WOTS_LEN], f[SPX_WOTS_LEN];
    unsigned char mz[SPX_N] = {0}, mf[SPX_N];
    unsigned char prf_key[SPX_N], prf_pub[SPX_N], prf_out[SPX_N];
    static const unsigned char prf_expected[SPX_N] = {
        0xe2,0x2a,0x32,0xe1,0x4a,0xd8,0x2f,0xdd,
        0xe7,0xb2,0x44,0x24,0x68,0xde,0x08,0x59,
        0xbb,0x0d,0x14,0x6f,0xd3,0x8c,0x8b,0xe9,
        0x7f,0x30,0x6e,0x8a,0xb4,0xbe,0xd8,0xf8
    };
    uint32_t prf_addr_words[8] = {0};
    unsigned sum_z = 0, sum_f = 0;

    if (!pk || !sk || !pk2 || !sk2 || !sig || !sig2 || !tmp) return 2;
    memset(mf, 0xff, sizeof(mf));
    memcpy(changed, msg, mlen);
    changed[0] ^= 1;

    init_random_number(&drng_algorithm, (unsigned char *)nonce, sizeof(nonce));
    result("keygen_1", crypto_sign_keypair(pk, sk) == 0);
    result("sign_1", crypto_sign_signature(sig, &siglen, msg, mlen, sk) == 0);
    result("published_signature_size", siglen == SPX_BYTES && SPX_BYTES == 43296);
    result("honest_verify", crypto_sign_verify(sig, siglen, msg, mlen, pk) == 0);

    result("sign_2_same_message", crypto_sign_signature(sig2, &siglen2, msg, mlen, sk) == 0);
    result("hedged_R_changes", memcmp(sig, sig2, SPX_N) != 0);
    result("second_honest_verify", crypto_sign_verify(sig2, siglen2, msg, mlen, pk) == 0);
    result("fresh_message_reject", crypto_sign_verify(sig, siglen, changed, mlen, pk) != 0);

    memcpy(tmp, sig, SPX_BYTES); tmp[0] ^= 1;
    result("changed_R_reject", crypto_sign_verify(tmp, siglen, msg, mlen, pk) != 0);
    memcpy(tmp, sig, SPX_BYTES); tmp[SPX_N] ^= 1;
    result("changed_FORC_node_reject", crypto_sign_verify(tmp, siglen, msg, mlen, pk) != 0);
    memcpy(tmp, sig, SPX_BYTES); tmp[SPX_N + SPX_FORS_BYTES] ^= 1;
    result("changed_WOTS_node_reject", crypto_sign_verify(tmp, siglen, msg, mlen, pk) != 0);
    result("truncated_signature_reject", crypto_sign_verify(sig, siglen - 1, msg, mlen, pk) != 0);
    result("extended_signature_reject", crypto_sign_verify(sig, siglen + 1, msg, mlen, pk) != 0);

    result("keygen_2", crypto_sign_keypair(pk2, sk2) == 0);
    result("independent_public_keys", memcmp(pk, pk2, SPX_PK_BYTES) != 0);
    result("wrong_independent_key_reject", crypto_sign_verify(sig, siglen, msg, mlen, pk2) != 0);

    set_chain_addr(a0, 0);
    set_chain_addr(a256, 256);
    result("full_width_chain_address", memcmp(a0, a256, sizeof(a0)) != 0 &&
           ((unsigned char *)a256)[26] == 1 && ((unsigned char *)a256)[27] == 0);

    for (unsigned i = 0; i < SPX_N; i++) {
        prf_pub[i] = (unsigned char)i;
        prf_key[i] = (unsigned char)(0x80 + i);
    }
    set_layer_addr(prf_addr_words, 3);
    set_tree_addr(prf_addr_words, UINT64_C(0x0102030405060708));
    set_type(prf_addr_words, SPX_ADDR_TYPE_FORSPRF);
    set_keypair_addr(prf_addr_words, 17);
    set_chain_addr(prf_addr_words, 256);
    set_hash_addr(prf_addr_words, 0);
    prf_addr(prf_out, prf_key, prf_pub, prf_addr_words);
    result("table_1_2_PRF_vector", memcmp(prf_out, prf_expected, SPX_N) == 0);

    chain_lengths(z, mz);
    chain_lengths(f, mf);
    for (unsigned i = 0; i < SPX_WOTS_LEN; i++) {
        sum_z += z[i]; sum_f += f[i];
    }
    result("WOTS_fixed_sum", sum_z == SPX_WOTS_S && sum_f == SPX_WOTS_S);
    result("WOTS_full_message_distinct", memcmp(z, f, sizeof(z)) != 0);

    printf(",\n  \"all_checks_pass\":%s\n}\n", all_true ? "true" : "false");
    free(tmp); free(sig2); free(sig); free(sk2); free(pk2); free(sk); free(pk);
    return all_true ? 0 : 1;
}

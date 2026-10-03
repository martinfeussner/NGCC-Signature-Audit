#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "auxfunc.h"


void initialize_hash_function(const unsigned char *pub_seed,
                              const unsigned char *sk_seed)
{
    (void)pub_seed; /* Suppress an 'unused parameter' warning. */
    (void)sk_seed;  /* Suppress an 'unused parameter' warning. */
}

/* Table 1.2 compressed-address encoding:
 * low layer byte || low 8 tree bytes || low type byte || final 12 bytes. */
static void compress_addr(unsigned char out[22], const uint32_t addr[8])
{
    const unsigned char *a = (const unsigned char *)addr;
    out[0] = a[SPX_OFFSET_LAYER];
    memcpy(out + 1, a + SPX_OFFSET_TREE, 8);
    out[9] = a[SPX_OFFSET_TYPE];
    memcpy(out + 10, a + 20, 12);
}

/* Table 1.2: Trunc_n(SM3(PK.seed || 0^(64-n) || ADRS_c || SK.seed)). */
void prf_addr(unsigned char *out, const unsigned char *key,
              const unsigned char *pub_seed, const uint32_t addr[8])
{
    unsigned char buf[64 + 22 + SPX_N];
    unsigned char temp_out[32];

    memcpy(buf, pub_seed, SPX_N);
    memset(buf + SPX_N, 0, 64 - SPX_N);
    compress_addr(buf + 64, addr);
    memcpy(buf + 64 + 22, key, SPX_N);

    sm3hash(256, buf, (unsigned long long)sizeof(buf) * 8, temp_out);
    memcpy(out, temp_out, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen)
{

    unsigned long long total_bytes = 2 * SPX_N + mlen;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (buf == NULL) {
        return; 
    }

    memcpy(buf, sk_prf, SPX_N);
    memcpy(buf + SPX_N, optrand, SPX_N);
    memcpy(buf + 2 * SPX_N, m, mlen);

    unsigned long long in_len_bits = total_bytes * 8;

    if (SPX_N <= 32) {
        unsigned char temp_out[32];
        sm3hash(256, buf, in_len_bits, temp_out);
        memcpy(R, temp_out, SPX_N);
    } else {
        unsigned long long out_len_bits = (unsigned long long)SPX_N * 8;
        pseudoXOF(out_len_bits, buf, in_len_bits, R);
    }
    free(buf);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen)
{
#define SPX_TREE_BITS (SPX_FULL_HEIGHT - (SPX_BOTTOM_TREE_HEIGHT))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS (SPX_BOTTOM_TREE_HEIGHT)
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf_out[SPX_DGST_BYTES];
    unsigned char *bufp = buf_out;

    unsigned long long total_bytes = SPX_N + SPX_PK_BYTES + mlen;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (buf == NULL) {
        return;
    }

    memcpy(buf, R, SPX_N);
    memcpy(buf + SPX_N, pk, SPX_PK_BYTES);
    memcpy(buf + SPX_N + SPX_PK_BYTES, m, mlen);

    unsigned long long in_len_bits = total_bytes * 8;
    unsigned long long out_len_bits = (unsigned long long)SPX_DGST_BYTES * 8;

    pseudoXOF(out_len_bits, buf, in_len_bits, buf_out);

    free(buf);
    
    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}

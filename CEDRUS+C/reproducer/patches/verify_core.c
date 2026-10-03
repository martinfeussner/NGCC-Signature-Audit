#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "auxfunc.h"
#include "context.h"
#include "counters.h"
#include "fors.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "verify_core.h"
#include "wots.h"

static int verify_internal(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pk, int strict_membership)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};
    uint32_t counter;

    if (siglen != SPX_BYTES) return -1;
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    counter = get_fors_counter(sig);
    if (hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen,
                     &ctx, &counter) == -1)
        return -1;
    sig += SPX_N + COUNTER_SIZE;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);
    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    uint32_t heights[SPX_D];
    uint32_t num_k = SPX_FULL_HEIGHT - SPX_TREE_HEIGHT * SPX_D;
    for (uint32_t j = 0; j < num_k; j++) heights[j] = SPX_TREE_HEIGHT + 1;
    for (uint32_t j = num_k; j < SPX_D; j++) heights[j] = SPX_TREE_HEIGHT;

    for (uint32_t i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);
        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);
        copy_keypair_addr(wots_pk_addr, wots_addr);

        counter = get_wots_counter(sig, heights[i]);
        sig += COUNTER_SIZE;
        if (strict_membership) {
            unsigned char digest[SPX_N], bitmask[SPX_N];
            uint32_t digest_addr[8] = {0};
            set_type(digest_addr, SPX_ADDR_TYPE_COMPRESS_WOTS);
            copy_keypair_addr(digest_addr, wots_addr);
            thash_init_bitmask(bitmask, 1, &ctx, digest_addr);
            ull_to_bytes(((unsigned char *)digest_addr) + SPX_OFFSET_COUNTER,
                         COUNTER_SIZE, counter);
            thash_fin(digest, root, 1, &ctx, digest_addr, bitmask);
            if (!wots_digest_valid(digest)) return -1;
        }
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr, counter);
        sig += SPX_WOTS_BYTES;
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);
        compute_root(root, leaf, idx_leaf, 0, sig, heights[i], &ctx, tree_addr);
        sig += heights[i] * SPX_N;

        if (i + 1 < SPX_D) {
            idx_leaf = (uint32_t)(tree & ((UINT64_C(1) << heights[i + 1]) - 1));
            tree >>= heights[i + 1];
        }
    }
    return memcmp(root, pub_root, SPX_N) ? -1 : 0;
}

int cedrus_c_verify_coherent(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pk)
{
    return verify_internal(sig, siglen, m, mlen, pk, 0);
}

int cedrus_c_verify_strict(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *pk)
{
    return verify_internal(sig, siglen, m, mlen, pk, 1);
}

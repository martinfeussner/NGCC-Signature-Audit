#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "params.h"

enum { DONORS = 3 };

static void put_index(unsigned char *m, unsigned coordinate, uint32_t value)
{
    unsigned offset = coordinate * SPX_FORS_HEIGHT;
    for (unsigned j = 0; j < SPX_FORS_HEIGHT; j++) {
        unsigned bit = offset + j;
        unsigned char mask = (unsigned char)(1u << (bit & 7));
        if ((value >> j) & 1u) m[bit >> 3] |= mask;
        else m[bit >> 3] &= (unsigned char)~mask;
    }
}

static uint32_t get_index(const unsigned char *m, unsigned coordinate)
{
    unsigned offset = coordinate * SPX_FORS_HEIGHT;
    uint32_t value = 0;
    for (unsigned j = 0; j < SPX_FORS_HEIGHT; j++) {
        unsigned bit = offset + j;
        value |= (uint32_t)((m[bit >> 3] >> (bit & 7)) & 1u) << j;
    }
    return value;
}

static void emit(const char *name, int value, int *first, int *all)
{
    printf("%s\"%s\":%s", *first ? "" : ",", name,
           value ? "true" : "false");
    *first = 0;
    *all &= value;
}

int main(void)
{
    const size_t component = (SPX_FORS_HEIGHT + 1u) * SPX_N;
    const size_t sigbytes = SPX_FORS_TREES * component;
    const uint32_t bound = UINT32_C(1) << SPX_FORS_HEIGHT;
    unsigned char *messages = calloc(DONORS, SPX_FORS_MSG_BYTES);
    unsigned char *sigs = calloc(DONORS, sigbytes);
    unsigned char *mixed = calloc(1, sigbytes);
    unsigned char *tmp = calloc(1, sigbytes);
    unsigned char roots[DONORS][SPX_N];
    unsigned char mixed_root[SPX_N], test_root[SPX_N];
    unsigned char target[SPX_FORS_MSG_BYTES];
    spx_ctx ctx = {0};
    uint32_t addr[8] = {0}, wrong_addr[8] = {0};
    int first = 1, all = 1, target_is_old = 0;

    if (!messages || !sigs || !mixed || !tmp) return 2;
    printf("{");
    memset(target, 0, sizeof target);
    for (unsigned i = 0; i < SPX_N; i++) {
        ctx.sk_seed[i] = (unsigned char)(0x31u + 7u * i);
        ctx.pub_seed[i] = (unsigned char)(0xa7u - 3u * i);
    }
    initialize_hash_function(&ctx);

    set_layer_addr(addr, 0);
    set_tree_addr(addr, UINT64_C(0x0123456789abcd));
    set_keypair_addr(addr, 3);
    memcpy(wrong_addr, addr, sizeof addr);
    set_keypair_addr(wrong_addr, 4);

    for (unsigned d = 0; d < DONORS; d++) {
        unsigned char *m = messages + d * SPX_FORS_MSG_BYTES;
        for (unsigned i = 0; i < SPX_FORS_TREES; i++) {
            uint32_t x = (uint32_t)((17u * i + 37u * d + 11u) % bound);
            put_index(m, i, x);
        }
        fors_sign(sigs + d * sigbytes, roots[d], m, &ctx, addr);
        fors_pk_from_sig(test_root, sigs + d * sigbytes, m, &ctx, addr);
        emit(d == 0 ? "donor0_self_verifies" :
             d == 1 ? "donor1_self_verifies" : "donor2_self_verifies",
             memcmp(test_root, roots[d], SPX_N) == 0, &first, &all);
    }
    emit("address_public_key_is_message_independent",
         memcmp(roots[0], roots[1], SPX_N) == 0 &&
         memcmp(roots[0], roots[2], SPX_N) == 0, &first, &all);

    for (unsigned i = 0; i < SPX_FORS_TREES; i++) {
        unsigned d = i % DONORS;
        const unsigned char *m = messages + d * SPX_FORS_MSG_BYTES;
        put_index(target, i, get_index(m, i));
        memcpy(mixed + i * component,
               sigs + d * sigbytes + i * component, component);
    }
    for (unsigned d = 0; d < DONORS; d++) {
        const unsigned char *m = messages + d * SPX_FORS_MSG_BYTES;
        target_is_old |= memcmp(target, m, SPX_FORS_MSG_BYTES) == 0;
    }
    emit("target_vector_absent_from_donors", !target_is_old, &first, &all);
    fors_pk_from_sig(mixed_root, mixed, target, &ctx, addr);
    emit("coordinate_mixed_root_matches", memcmp(mixed_root, roots[0], SPX_N) == 0,
         &first, &all);

    memcpy(tmp, mixed, sigbytes);
    tmp[SPX_N] ^= 1;
    fors_pk_from_sig(test_root, tmp, target, &ctx, addr);
    emit("authentication_tamper_changes_root", memcmp(test_root, roots[0], SPX_N) != 0,
         &first, &all);

    memcpy(tmp, mixed, sigbytes);
    tmp[0] ^= 1;
    fors_pk_from_sig(test_root, tmp, target, &ctx, addr);
    emit("secret_tamper_changes_root", memcmp(test_root, roots[0], SPX_N) != 0,
         &first, &all);

    fors_pk_from_sig(test_root, mixed, target, &ctx, wrong_addr);
    emit("wrong_complete_address_changes_root", memcmp(test_root, roots[0], SPX_N) != 0,
         &first, &all);

    put_index(target, 0, (get_index(target, 0) + 1u) % bound);
    fors_pk_from_sig(test_root, mixed, target, &ctx, addr);
    emit("mismatched_target_index_changes_root", memcmp(test_root, roots[0], SPX_N) != 0,
         &first, &all);

    printf(",\"parameter_set\":\"%u-bit/%u-trees/height-%u\"",
           8u * SPX_N, SPX_FORS_TREES, SPX_FORS_HEIGHT);
    printf(",\"all_checks_pass\":%s}\n", all ? "true" : "false");
    free(tmp); free(mixed); free(sigs); free(messages);
    return all ? 0 : 1;
}

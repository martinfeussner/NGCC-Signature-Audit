#include "challenge.h"
#include "instances.h"
#include "random_oracle.h"
#include "vole.h"
#include "xof.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const galas_paramset_t *p;
    uint8_t *signature;
    size_t signature_len;
    uint8_t iv[GALAS_IV_SIZE];
    uint16_t opens[GALAS_MAX_TAU];
    uint8_t *tree;
    uint8_t *known;
    uint8_t *hidden;
    unsigned used_seeds;
} public_opening;

static unsigned wbytes(unsigned lambda) { return 5u * lambda / 16u; }
static unsigned ebytes(unsigned lambda) { return (11u * lambda / 2u + 16u) / 8u; }
static size_t cbytes(const galas_paramset_t *p) {
    return (size_t)(p->p.tau - 1u) * ebytes(p->p.lambda);
}
static size_t d_offset(const galas_paramset_t *p) {
    return cbytes(p) + p->p.lambda / 8u + 2u;
}
static size_t open_offset(const galas_paramset_t *p) {
    return d_offset(p) + wbytes(p->p.lambda) + 2u * (p->p.lambda / 8u);
}
static size_t open_bytes(const galas_paramset_t *p) {
    unsigned lb = p->p.lambda / 8u;
    return (size_t)(2u * p->p.tau + p->p.T_open) * lb;
}
static size_t delta_offset(const galas_paramset_t *p) {
    return open_offset(p) + open_bytes(p);
}
static size_t ivpre_offset(const galas_paramset_t *p) {
    return delta_offset(p) + p->p.lambda / 8u;
}
static size_t expected_signature_bytes(const galas_paramset_t *p) {
    return ivpre_offset(p) + GALAS_IV_SIZE + 4u;
}

static int getbit(const uint8_t *v, uint32_t i) {
    return (v[i >> 3] >> (i & 7u)) & 1u;
}
static void putbit(uint8_t *v, uint32_t i) {
    v[i >> 3] |= (uint8_t)(1u << (i & 7u));
}
static uint32_t physical_leaf(const galas_paramset_t *p, unsigned i, unsigned j) {
    uint32_t half = 1u << (p->p.k - 1u);
    if (j < half) return p->p.L - 1u + p->p.tau * j + i;
    return p->p.L - 1u + p->p.tau * half + p->p.tau1 * (j - half) + i;
}

static int read_all(const char *path, uint8_t **out, size_t *len) {
    FILE *f = fopen(path, "rb");
    long n;
    if (!f || fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET)) {
        if (f) fclose(f);
        return -1;
    }
    *out = malloc(n ? (size_t)n : 1u);
    if (!*out || (n && fread(*out, 1, (size_t)n, f) != (size_t)n)) {
        free(*out); fclose(f); return -1;
    }
    fclose(f); *len = (size_t)n; return 0;
}
static int write_all(const char *path, const uint8_t *v, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(v, 1, len, f) != len) { fclose(f); return -1; }
    return fclose(f);
}

static void expand_node(uint8_t *tree, uint32_t node, const uint8_t iv[GALAS_IV_SIZE],
                        unsigned lambda) {
    unsigned lb = lambda / 8u, total = 2u * lb;
    uint8_t *parent = tree + (size_t)node * lb;
    uint8_t *children = tree + (size_t)(2u * node + 1u) * lb;
    unsigned blocks = (total + 15u) / 16u;
    unsigned first = 4u - (blocks & 1u);
    unsigned produced = 0, counter = 0;
    if (first > blocks) first = blocks;
    while (produced < total) {
        unsigned count = counter == 0 ? first : 2u;
        uint8_t out[64];
        xof_ctx x;
        if (count > blocks - counter) count = blocks - counter;
        xof_init(&x, lambda, XOF_DOMAIN_TREE_PRG);
        xof_update(&x, parent, lb);
        xof_update(&x, iv, GALAS_IV_SIZE);
        xof_update_u32(&x, node);
        xof_update_u32(&x, counter);
        xof_final(&x);
        xof_squeeze(&x, out, (size_t)count * 16u);
        xof_clear(&x);
        {
            unsigned take = total - produced;
            if (take > count * 16u) take = count * 16u;
            memcpy(children + produced, out, take);
            produced += take;
        }
        counter += count;
    }
}

static int parse_opening(public_opening *o, const char *path, galas_instance_id_t id) {
    unsigned lb;
    uint32_t nodes;
    const uint8_t *seed, *seed_limit;
    memset(o, 0, sizeof(*o));
    o->p = galas_get_paramset(id);
    lb = o->p->p.lambda / 8u;
    if (read_all(path, &o->signature, &o->signature_len) ||
        o->signature_len != expected_signature_bytes(o->p)) return -1;
    {
        galas_H4_ctx h;
        galas_H4_init(&h, o->p->p.lambda);
        galas_H4_update(&h, o->signature + ivpre_offset(o->p));
        galas_H4_final(&h, o->iv);
    }
    if (!galas_decode_all_chall_3(o->opens,
                                  o->signature + delta_offset(o->p), o->p)) return -2;
    nodes = 2u * o->p->p.L - 1u;
    o->tree = calloc(nodes, lb);
    o->known = calloc((nodes + 7u) / 8u, 1u);
    o->hidden = calloc((nodes + 7u) / 8u, 1u);
    if (!o->tree || !o->known || !o->hidden) return -3;
    for (unsigned i = 0; i < o->p->p.tau; ++i)
        putbit(o->hidden, physical_leaf(o->p, i, o->opens[i]));
    seed = o->signature + open_offset(o->p) + (size_t)2u * o->p->p.tau * lb;
    seed_limit = seed + (size_t)o->p->p.T_open * lb;
    for (int32_t a = (int32_t)o->p->p.L - 2; a >= 0; --a) {
        uint32_t left = 2u * (uint32_t)a + 1u;
        int lh = getbit(o->hidden, left), rh = getbit(o->hidden, left + 1u);
        if (lh || rh) putbit(o->hidden, (uint32_t)a);
        if (lh != rh) {
            uint32_t sibling = left + (uint32_t)lh;
            if (seed + lb > seed_limit) return -4;
            memcpy(o->tree + (size_t)sibling * lb, seed, lb);
            putbit(o->known, sibling);
            seed += lb;
            o->used_seeds++;
        }
    }
    while (seed < seed_limit) if (*seed++) return -5;
    for (uint32_t a = 0; a < o->p->p.L - 1u; ++a) {
        if (!getbit(o->known, a)) continue;
        expand_node(o->tree, a, o->iv, o->p->p.lambda);
        putbit(o->known, 2u * a + 1u);
        putbit(o->known, 2u * a + 2u);
    }
    return 0;
}

static void clear_opening(public_opening *o) {
    free(o->signature); free(o->tree); free(o->known); free(o->hidden);
    memset(o, 0, sizeof(*o));
}

static void leaf_to_sd(uint8_t *sd, const uint8_t *node,
                       const uint8_t iv[GALAS_IV_SIZE], uint32_t tweak,
                       unsigned lambda) {
    unsigned lb = lambda / 8u;
    uint8_t zero = 0, out[3u * GALAS_MAX_LAMBDA_BYTES];
    xof_ctx x;
    xof_init(&x, lambda, XOF_DOMAIN_LEAF);
    xof_update(&x, node, lb);
    xof_update(&x, iv, GALAS_IV_SIZE);
    xof_update_u32(&x, tweak);
    xof_update(&x, &zero, 1u);
    xof_final(&x);
    xof_squeeze(&x, out, 3u * lb);
    xof_clear(&x);
    memcpy(sd, out, lb);
}

int main(int argc, char **argv) {
    public_opening shortv = {0}, fastv = {0};
    uint8_t *sd = NULL, *u = NULL, *tags = NULL, *w = NULL;
    const galas_paramset_t *p;
    unsigned lb, leaves, missing = 0, supplied = 0, overlap_checked = 0;
    int only_fast = 0, ret = 1;
    if (argc == 5 && !strcmp(argv[4], "--fast-only")) only_fast = 1;
    if (argc != 4 && !only_fast) {
        fprintf(stderr, "usage: %s SIG_160S SIG_160F OUTPUT_KEY [--fast-only]\n", argv[0]);
        return 2;
    }
    if (parse_opening(&shortv, argv[1], GALAS_160S) ||
        parse_opening(&fastv, argv[2], GALAS_160F)) {
        fprintf(stderr, "parse failure\n");
        ret = 3; goto done;
    }
    if (memcmp(shortv.iv, fastv.iv, GALAS_IV_SIZE) ||
        memcmp(shortv.signature + ivpre_offset(shortv.p),
               fastv.signature + ivpre_offset(fastv.p), GALAS_IV_SIZE)) {
        fprintf(stderr, "state mismatch\n");
        ret = 4; goto done;
    }
    p = fastv.p; lb = p->p.lambda / 8u;
    {
        uint32_t common = 2u * p->p.L - 1u;
        for (uint32_t a = 0; a < common; ++a) {
            if (getbit(shortv.known, a) && getbit(fastv.known, a)) {
                ++overlap_checked;
                if (memcmp(shortv.tree + (size_t)a * lb,
                           fastv.tree + (size_t)a * lb, lb)) {
                    fprintf(stderr, "shared-node inconsistency at %u\n", a);
                    ret = 5; goto done;
                }
            }
        }
    }
    leaves = galas_bavc_leaves(0, p);
    sd = malloc((size_t)leaves * lb);
    u = malloc(ebytes(p->p.lambda));
    tags = malloc((size_t)galas_bavc_depth(0, p) * ebytes(p->p.lambda));
    w = malloc(wbytes(p->p.lambda));
    if (!sd || !u || !tags || !w) goto done;
    for (unsigned j = 0; j < leaves; ++j) {
        uint32_t a = physical_leaf(p, 0, j);
        const uint8_t *node = NULL;
        if (getbit(fastv.known, a)) node = fastv.tree + (size_t)a * lb;
        else {
            ++missing;
            if (only_fast) {
                fprintf(stderr, "isolated transcript missing target node=%u\n", a);
                ret = 6; goto done;
            }
            if (a < 2u * shortv.p->p.L - 1u && getbit(shortv.known, a)) {
                node = shortv.tree + (size_t)a * lb;
                ++supplied;
            }
        }
        if (!node) {
            fprintf(stderr, "complementary opening failed at node=%u\n", a);
            ret = 7; goto done;
        }
        leaf_to_sd(sd + (size_t)j * lb, node, fastv.iv,
                   p->p.L - 1u, p->p.lambda);
    }
    if (galas_convert_to_vole(fastv.iv, sd, 0, 0, ebytes(p->p.lambda),
                              u, tags, p) < 0) goto done;
    for (unsigned i = 0; i < wbytes(p->p.lambda); ++i)
        w[i] = fastv.signature[d_offset(p) + i] ^ u[i];
    if (write_all(argv[3], w, lb)) goto done;
    printf("recovery=ok common_state=1 target_missing=%u supplied_by_short=%u overlap_nodes_checked=%u short_open_seeds=%u fast_open_seeds=%u\n",
           missing, supplied, overlap_checked, shortv.used_seeds, fastv.used_seeds);
    printf("key=");
    for (unsigned i = 0; i < lb; ++i) printf("%02x", w[i]);
    putchar('\n');
    ret = 0;
done:
    free(sd); free(u); free(tags); free(w);
    clear_opening(&shortv); clear_opening(&fastv);
    return ret;
}

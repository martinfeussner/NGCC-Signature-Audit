#include "instances.h"
#include "challenge.h"
#include "random_oracle.h"
#include "vole.h"
#include "xof.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PAIR_S_ID
#define PAIR_S_ID GALAS_160S
#endif
#ifndef PAIR_F_ID
#define PAIR_F_ID GALAS_160F
#endif
#ifndef PAIR_LABEL
#define PAIR_LABEL "160"
#endif

typedef struct {
    const galas_paramset_t *ps;
    uint8_t *sig;
    size_t sig_len;
    uint8_t iv[GALAS_IV_SIZE];
    uint16_t delta[GALAS_MAX_TAU];
    uint8_t *known;
    uint8_t *nodes;
    uint8_t *hidden;
    size_t seeds_used;
} opened_view;

static unsigned witness_bits(unsigned lambda) { return 5u * lambda / 2u; }
static unsigned witness_bytes(unsigned lambda) { return witness_bits(lambda) / 8u; }
static unsigned ellhat_bits(unsigned lambda) { return witness_bits(lambda) + 3u * lambda + 16u; }
static unsigned ellhat_bytes(unsigned lambda) { return ellhat_bits(lambda) / 8u; }
static size_t off_vc(const galas_paramset_t *p) {
    return (size_t)(p->p.tau - 1u) * ellhat_bytes(p->p.lambda);
}
static size_t off_d(const galas_paramset_t *p) { return off_vc(p) + p->p.lambda / 8u + 2u; }
static size_t off_qs(const galas_paramset_t *p) { return off_d(p) + witness_bytes(p->p.lambda); }
static size_t off_decom(const galas_paramset_t *p) { return off_qs(p) + 2u * (p->p.lambda / 8u); }
static size_t decom_len(const galas_paramset_t *p) {
    unsigned lb = p->p.lambda / 8u;
    return (size_t)p->p.tau * 2u * lb + (size_t)p->p.T_open * lb;
}
static size_t off_delta(const galas_paramset_t *p) { return off_decom(p) + decom_len(p); }
static size_t off_ivpre(const galas_paramset_t *p) { return off_delta(p) + p->p.lambda / 8u; }
static size_t total_len(const galas_paramset_t *p) { return off_ivpre(p) + GALAS_IV_SIZE + 4u; }

static int bit_get(const uint8_t *a, uint32_t i) { return (a[i >> 3] >> (i & 7u)) & 1u; }
static void bit_set(uint8_t *a, uint32_t i) { a[i >> 3] |= (uint8_t)(1u << (i & 7u)); }
static void bit_clear(uint8_t *a, uint32_t i) { a[i >> 3] &= (uint8_t)~(1u << (i & 7u)); }

static uint32_t pos_in_tree(unsigned i, unsigned j, const galas_paramset_t *ps) {
    uint32_t short_len = 1u << (ps->p.k - 1u);
    if (j < short_len) return ps->p.L - 1u + (uint32_t)ps->p.tau * j + i;
    return ps->p.L - 1u + (uint32_t)ps->p.tau * short_len +
           (uint32_t)ps->p.tau1 * (j & (short_len - 1u)) + i;
}

static void tree_prg(uint8_t *nodes, uint32_t alpha, const uint8_t *iv,
                     unsigned lambda, unsigned lb) {
    uint8_t *parent = nodes + (size_t)alpha * lb;
    uint8_t *out = nodes + (size_t)(2u * alpha + 1u) * lb;
    unsigned total = 2u * lb, blocks = (total + 15u) / 16u;
    unsigned first_blocks = 4u - (blocks & 1u), done = 0;
    if (first_blocks > blocks) first_blocks = blocks;
    for (unsigned counter = 0; done < total;) {
        unsigned nblocks = counter == 0 ? first_blocks : 2u;
        uint8_t block[64];
        xof_ctx ctx;
        if (nblocks > blocks - counter) nblocks = blocks - counter;
        xof_init(&ctx, lambda, XOF_DOMAIN_TREE_PRG);
        xof_update(&ctx, parent, lb);
        xof_update(&ctx, iv, GALAS_IV_SIZE);
        xof_update_u32(&ctx, alpha);
        xof_update_u32(&ctx, counter);
        xof_final(&ctx);
        xof_squeeze(&ctx, block, (size_t)nblocks * 16u);
        xof_clear(&ctx);
        unsigned take = total - done, produced = nblocks * 16u;
        if (take > produced) take = produced;
        memcpy(out + done, block, take);
        done += take;
        counter += nblocks;
    }
}

static void leaf_expand(uint8_t *sd, const uint8_t *node, const uint8_t *iv,
                        uint32_t tweak, unsigned lambda, unsigned lb) {
    uint8_t out[3u * GALAS_MAX_LAMBDA_BYTES], zero = 0;
    xof_ctx ctx;
    xof_init(&ctx, lambda, XOF_DOMAIN_LEAF);
    xof_update(&ctx, node, lb);
    xof_update(&ctx, iv, GALAS_IV_SIZE);
    xof_update_u32(&ctx, tweak);
    xof_update(&ctx, &zero, 1u);
    xof_final(&ctx);
    xof_squeeze(&ctx, out, (size_t)3u * lb);
    xof_clear(&ctx);
    memcpy(sd, out, lb);
}

static int read_file(const char *path, uint8_t **out, size_t *len) {
    FILE *f = fopen(path, "rb");
    long n;
    if (!f || fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        if (f) fclose(f);
        return -1;
    }
    *out = malloc(n ? (size_t)n : 1u);
    if (!*out || (n && fread(*out, 1, (size_t)n, f) != (size_t)n)) {
        free(*out); fclose(f); return -1;
    }
    fclose(f); *len = (size_t)n; return 0;
}

static int write_file(const char *path, const uint8_t *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (n && fwrite(p, 1, n, f) != n) { fclose(f); return -1; }
    return fclose(f);
}

static int open_view(opened_view *v, const char *path, galas_instance_id_t id) {
    const uint8_t *decom, *seeds, *seeds_end;
    uint32_t total_nodes;
    unsigned lb;
    memset(v, 0, sizeof(*v));
    v->ps = galas_get_paramset(id);
    lb = v->ps->p.lambda / 8u;
    if (read_file(path, &v->sig, &v->sig_len) != 0 || v->sig_len != total_len(v->ps)) return -1;
    {
        galas_H4_ctx h;
        galas_H4_init(&h, v->ps->p.lambda);
        galas_H4_update(&h, v->sig + off_ivpre(v->ps));
        galas_H4_final(&h, v->iv);
    }
    if (!galas_decode_all_chall_3(v->delta, v->sig + off_delta(v->ps), v->ps)) return -1;
    total_nodes = 2u * v->ps->p.L - 1u;
    v->known = calloc((total_nodes + 7u) / 8u, 1u);
    v->hidden = calloc((total_nodes + 7u) / 8u, 1u);
    v->nodes = calloc((size_t)total_nodes, lb);
    if (!v->known || !v->hidden || !v->nodes) return -1;
    for (unsigned i = 0; i < v->ps->p.tau; ++i)
        bit_set(v->hidden, pos_in_tree(i, v->delta[i], v->ps));
    decom = v->sig + off_decom(v->ps);
    seeds = decom + (size_t)v->ps->p.tau * 2u * lb;
    seeds_end = seeds + (size_t)v->ps->p.T_open * lb;
    for (int32_t alpha = (int32_t)v->ps->p.L - 2; alpha >= 0; --alpha) {
        uint32_t left = 2u * (uint32_t)alpha + 1u, right = left + 1u;
        int hl = bit_get(v->hidden, left), hr = bit_get(v->hidden, right);
        if (hl || hr) bit_set(v->hidden, (uint32_t)alpha);
        else bit_clear(v->hidden, (uint32_t)alpha);
        if (hl ^ hr) {
            uint32_t sibling = left + (uint32_t)hl;
            if (seeds + lb > seeds_end) return -1;
            memcpy(v->nodes + (size_t)sibling * lb, seeds, lb);
            bit_set(v->known, sibling);
            seeds += lb;
            ++v->seeds_used;
        }
    }
    while (seeds < seeds_end) if (*seeds++) return -1;
    for (uint32_t alpha = 0; alpha < v->ps->p.L - 1u; ++alpha) {
        if (!bit_get(v->known, alpha)) continue;
        tree_prg(v->nodes, alpha, v->iv, v->ps->p.lambda, lb);
        bit_set(v->known, 2u * alpha + 1u);
        bit_set(v->known, 2u * alpha + 2u);
    }
    return 0;
}

static void close_view(opened_view *v) {
    free(v->sig); free(v->known); free(v->hidden); free(v->nodes);
    memset(v, 0, sizeof(*v));
}

static int node_from(const opened_view *primary, const opened_view *aux,
                     uint32_t alpha, uint8_t *out, int *from_aux) {
    unsigned lb = primary->ps->p.lambda / 8u;
    uint32_t primary_nodes = 2u * primary->ps->p.L - 1u;
    uint32_t aux_nodes = 2u * aux->ps->p.L - 1u;
    if (alpha < primary_nodes && bit_get(primary->known, alpha)) {
        memcpy(out, primary->nodes + (size_t)alpha * lb, lb);
        if (alpha < aux_nodes && bit_get(aux->known, alpha) &&
            memcmp(out, aux->nodes + (size_t)alpha * lb, lb) != 0) return -2;
        *from_aux = 0;
        return 0;
    }
    if (alpha < aux_nodes && bit_get(aux->known, alpha)) {
        memcpy(out, aux->nodes + (size_t)alpha * lb, lb);
        *from_aux = 1;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    opened_view s, f;
    const galas_paramset_t *p;
    uint8_t *sd = NULL, *u = NULL, *vtmp = NULL, *w = NULL;
    unsigned lb, Ni, eb, wb, from_aux_count = 0, missing_primary = 0;
    int rc = 1, primary_only = 0;
    if (argc == 5 && strcmp(argv[4], "--primary-only") == 0) primary_only = 1;
    if (argc != 4 && !primary_only) {
        fprintf(stderr, "usage: %s SIG_" PAIR_LABEL "S SIG_" PAIR_LABEL "F RECOVERED_SK [--primary-only]\n", argv[0]);
        return 2;
    }
    if (open_view(&s, argv[1], PAIR_S_ID) != 0 ||
        open_view(&f, argv[2], PAIR_F_ID) != 0) {
        fprintf(stderr, "opening parse/reconstruction failed\n");
        return 3;
    }
    if (memcmp(s.iv, f.iv, GALAS_IV_SIZE) != 0 ||
        memcmp(s.sig + off_ivpre(s.ps), f.sig + off_ivpre(f.ps), GALAS_IV_SIZE) != 0) {
        fprintf(stderr, "cross-variant IV state is not shared\n");
        goto out;
    }
    p = f.ps; lb = p->p.lambda / 8u; Ni = galas_bavc_leaves(0, p);
    eb = ellhat_bytes(p->p.lambda); wb = witness_bytes(p->p.lambda);
    sd = malloc((size_t)Ni * lb); u = malloc(eb);
    vtmp = malloc((size_t)galas_bavc_depth(0, p) * eb); w = malloc(wb);
    if (!sd || !u || !vtmp || !w) goto out;
    for (unsigned j = 0; j < Ni; ++j) {
        uint32_t alpha = pos_in_tree(0, j, p);
        uint8_t node[GALAS_MAX_LAMBDA_BYTES];
        int from_aux = 0, nr;
        if (!bit_get(f.known, alpha)) ++missing_primary;
        if (primary_only && !bit_get(f.known, alpha)) {
            printf("recover=blocked target=Galas-" PAIR_LABEL "F reason=missing_hidden_tree0_leaf j=%u alpha=%u\n",
                   j, alpha);
            rc = 5;
            goto out;
        }
        nr = node_from(&f, &s, alpha, node, &from_aux);
        if (nr != 0) {
            fprintf(stderr, "unrecovered target leaf j=%u alpha=%u rc=%d\n", j, alpha, nr);
            goto out;
        }
        if (from_aux) ++from_aux_count;
        leaf_expand(sd + (size_t)j * lb, node, f.iv,
                    p->p.L - 1u, p->p.lambda, lb);
    }
    galas_convert_to_vole(f.iv, sd, 0, 0, eb, u, vtmp, p);
    for (unsigned i = 0; i < wb; ++i) w[i] = f.sig[off_d(p) + i] ^ u[i];
    if (write_file(argv[3], w, lb) != 0) goto out;
    printf("recover=ok target=Galas-" PAIR_LABEL "F same_iv=1 primary_missing=%u auxiliary_resolved=%u\n",
           missing_primary, from_aux_count);
    printf("s_opened_seeds=%zu f_opened_seeds=%zu recovered_key_hex=", s.seeds_used, f.seeds_used);
    for (unsigned i = 0; i < lb; ++i) printf("%02x", w[i]);
    putchar('\n');
    rc = 0;
out:
    free(sd); free(u); free(vtmp); free(w);
    close_view(&s); close_view(&f);
    return rc;
}

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "drng.h"
#include "uvw.h"

DRNG_ctx drng_algorithm;
DRNG_ctx *uvw_drng = &drng_algorithm;

extern void hash_to_vf3(shake256_ctx *ctx, vf3_e **out, size_t len);
extern void dec_z(const mf3_e *h_z, const vf3_e *s2, vf3_e **e2);
extern void dec_xy(const mf3_e *h_xy, const vf3_e *s1, const vf3_e *e2,
                   vf3_e **e1, size_t w);

typedef struct {
    size_t a, b;
    uint8_t dominant_ratio;
    double score, margin;
} pair_candidate;

typedef struct {
    uint64_t hash;
    uint32_t index;
} hash_item;

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

static void fail(const char *s) {
    fprintf(stderr, "%s%s%s\n", s, errno ? ": " : "", errno ? strerror(errno) : "");
    exit(1);
}

/* Match serialize_sn() in the submitted API.  uvw_write_signature() is an
 * internal file format and prepends the eight-byte string "UVWSSIGN". */
static size_t write_api_signature(const char *path, const uvw_signature *sig) {
    const size_t e_bytes = sig->e->alloc * sizeof(uint64_t);
    const size_t size = 12 + sig->param.lambda / 8 + 2 * e_bytes;
    unsigned char *buf = malloc(size);
    if (!buf) fail("allocate API signature");

    const uint16_t parameters[6] = {
        (uint16_t)sig->param.lambda, (uint16_t)sig->param.n,
        (uint16_t)sig->param.k,      (uint16_t)sig->param.k1,
        (uint16_t)sig->param.k2,     (uint16_t)sig->param.w,
    };
    size_t pos = 0;
    for (size_t i = 0; i < 6; i++) {
        memcpy(buf + pos, &parameters[i], sizeof(parameters[i]));
        pos += sizeof(parameters[i]);
    }
    memcpy(buf + pos, sig->r, sig->param.lambda / 8);
    pos += sig->param.lambda / 8;
    memcpy(buf + pos, sig->e->r0, e_bytes);
    pos += e_bytes;
    memcpy(buf + pos, sig->e->r1, e_bytes);
    pos += e_bytes;
    if (pos != size) fail("API signature length mismatch");

    FILE *out = fopen(path, "wb");
    if (!out) fail("open API signature output");
    if (fwrite(buf, 1, size, out) != size || fclose(out))
        fail("write API signature");
    free(buf);
    return size;
}

static uint8_t public_coeff(const uvw_public_key *pk, size_t row, size_t col) {
    const size_t m = pk->param.n - pk->param.k;
    return col < m ? (uint8_t)(row == col) : mf3_coeff(pk->r, row, col - m);
}

static pair_candidate *read_candidates(const char *path, size_t *count) {
    FILE *f = fopen(path, "r");
    if (!f) fail("open candidates");
    char line[4096];
    if (!fgets(line, sizeof(line), f)) fail("read candidate header");
    size_t cap = 4096, n = 0;
    pair_candidate *v = malloc(cap * sizeof(*v));
    if (!v) fail("malloc candidates");
    while (fgets(line, sizeof(line), f)) {
        pair_candidate c = {0};
        int fields = sscanf(line, "%zu%zu%hhu%lf%lf", &c.a, &c.b,
                            &c.dominant_ratio, &c.score, &c.margin);
        if (fields < 3) continue;
        if (n == cap) {
            cap *= 2;
            v = realloc(v, cap * sizeof(*v));
            if (!v) fail("realloc candidates");
        }
        v[n++] = c;
    }
    fclose(f);
    *count = n;
    return v;
}

static vf3_e *public_column(const uvw_public_key *pk, size_t col) {
    const size_t m = pk->param.n - pk->param.k;
    vf3_e *v = vf3_alloc(m);
    for (size_t r = 0; r < m; r++) vf3_set_coeff(r, v, public_coeff(pk, r, col));
    return v;
}

static uint64_t hash_vector(const vf3_e *v) {
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < v->alloc; i++) {
        h ^= v->r0[i]; h *= UINT64_C(1099511628211);
        h ^= v->r1[i]; h *= UINT64_C(1099511628211);
    }
    return h;
}

static int compare_hash_item(const void *aa, const void *bb) {
    const hash_item *a = aa, *b = bb;
    if (a->hash < b->hash) return -1;
    if (a->hash > b->hash) return 1;
    return (a->index > b->index) - (a->index < b->index);
}

static size_t first_nonzero(const vf3_e *v) {
    for (size_t i = 0; i < v->size; i++) if (vf3_get_element(i, v)) return i;
    return SIZE_MAX;
}

static void split_coordinates(const vf3_e *v, const size_t *pivots, size_t top_dim,
                              const size_t *free_cols, size_t bottom_dim,
                              vf3_e *top, vf3_e *free_part) {
    for (size_t i = 0; i < top_dim; i++)
        vf3_set_coeff(i, top, vf3_get_element(pivots[i], v));
    for (size_t i = 0; i < bottom_dim; i++)
        vf3_set_coeff(i, free_part, vf3_get_element(free_cols[i], v));
}

static void quotient(vf3_e *out, const vf3_e *v, const mf3_e *a,
                     const size_t *pivots, const size_t *free_cols) {
    vf3_e *top = vf3_alloc(a->n_row);
    vf3_e *free_part = vf3_alloc(a->n_col);
    vf3_e *product = vf3_alloc(a->n_col);
    split_coordinates(v, pivots, a->n_row, free_cols, a->n_col, top, free_part);
    mf3_product_vector_matrix(product, top, a);
    vf3_vector_sub(out, free_part, product);
    vf3_free(product);
    vf3_free(free_part);
    vf3_free(top);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s PUBLIC_KEY CANDIDATES SEED_COUNT API_SIGNATURE_OUT\n", argv[0]);
        return 2;
    }
    const size_t seed_count = strtoull(argv[3], NULL, 10);
    FILE *pkf = fopen(argv[1], "rb");
    if (!pkf) fail("open public key");
    uvw_public_key pk = uvw_read_public_key(pkf);
    fclose(pkf);
    const uvw_param param = pk.param;
    const size_t m = param.n - param.k;
    const size_t top_dim = param.n / 2 - param.k1;
    const size_t bottom_dim = param.n / 2 - param.k2;
    const size_t pair_count = param.n / 2;

    size_t candidate_count = 0;
    pair_candidate *candidates = read_candidates(argv[2], &candidate_count);
    if (seed_count < top_dim || seed_count > candidate_count) fail("invalid seed count");
    fprintf(stderr, "candidates=%zu seed_count=%zu\n", candidate_count, seed_count);

    double t0 = now_seconds();
    mf3_e *seed_rows = mf3_alloc(seed_count, m);
    for (size_t i = 0; i < seed_count; i++) {
        const pair_candidate c = candidates[i];
        if (c.a >= param.n || c.b >= param.n || (c.dominant_ratio != 1 && c.dominant_ratio != 2))
            fail("invalid candidate row");
        const uint8_t rel = (uint8_t)(3 - c.dominant_ratio);
        for (size_t r = 0; r < m; r++) {
            const uint8_t x = public_coeff(&pk, r, c.a);
            const uint8_t y = public_coeff(&pk, r, c.b);
            mf3_setcoeff(seed_rows, i, r, (uint8_t)((x + rel * y) % 3));
        }
    }
    mf3_e *u_rref = NULL;
    size_t rank = gauss_jordan_elimination(seed_rows, &u_rref, NULL, NULL);
    fprintf(stderr, "candidate_span_rank=%zu expected=%zu elapsed=%.3f\n",
            rank, top_dim, now_seconds() - t0);
    if (rank < top_dim) fail("candidate sums do not span the expected subspace");

    if (rank > top_dim) {
        t0 = now_seconds();
        mf3_e *transpose = mf3_alloc(m, seed_count);
        mf3_transpose_and_copy(transpose, seed_rows);
        mf3_e *transpose_rref = NULL;
        const size_t transpose_rank =
            gauss_jordan_elimination(transpose, &transpose_rref, NULL, NULL);
        mf3_free(transpose);
        if (transpose_rank != rank) fail("row/column rank mismatch");

        uint8_t *pivot_candidate = calloc(seed_count, 1);
        uint8_t *essential = calloc(seed_count, 1);
        size_t *transpose_pivots = malloc(rank * sizeof(*transpose_pivots));
        if (!pivot_candidate || !essential || !transpose_pivots)
            fail("allocate dependency analysis");
        for (size_t i = 0; i < rank; i++) {
            transpose_pivots[i] = first_nonzero(&transpose_rref->rows[i]);
            if (transpose_pivots[i] == SIZE_MAX) fail("zero transpose RREF row");
            pivot_candidate[transpose_pivots[i]] = 1;
        }
        size_t essential_count = 0;
        for (size_t i = 0; i < rank; i++) {
            int participates = 0;
            for (size_t j = 0; j < seed_count; j++) {
                if (!pivot_candidate[j] && mf3_coeff(transpose_rref, i, j)) {
                    participates = 1;
                    break;
                }
            }
            if (!participates) {
                essential[transpose_pivots[i]] = 1;
                essential_count++;
            }
        }
        mf3_free(transpose_rref);

        const size_t clean_count = seed_count - essential_count;
        mf3_e *clean = mf3_alloc(clean_count, m);
        size_t dst = 0;
        for (size_t i = 0; i < seed_count; i++)
            if (!essential[i]) vf3_copy(&clean->rows[dst++], &seed_rows->rows[i]);
        mf3_free(u_rref);
        u_rref = NULL;
        rank = gauss_jordan_elimination(clean, &u_rref, NULL, NULL);
        mf3_free(clean);
        fprintf(stderr,
                "dependency_outliers=%zu clean_candidates=%zu clean_rank=%zu elapsed=%.3f\n",
                essential_count, clean_count, rank, now_seconds() - t0);
        free(transpose_pivots);
        free(essential);
        free(pivot_candidate);
        if (rank != top_dim || clean_count <= top_dim)
            fail("dependency filtering did not isolate the expected subspace");
    }
    mf3_free(seed_rows);

    size_t *pivots = malloc(top_dim * sizeof(*pivots));
    size_t *free_cols = malloc(bottom_dim * sizeof(*free_cols));
    uint8_t *is_pivot = calloc(m, 1);
    if (!pivots || !free_cols || !is_pivot) fail("allocate coordinate maps");
    for (size_t i = 0; i < top_dim; i++) {
        pivots[i] = first_nonzero(&u_rref->rows[i]);
        if (pivots[i] == SIZE_MAX) fail("zero RREF basis row");
        is_pivot[pivots[i]] = 1;
    }
    size_t fp = 0;
    for (size_t i = 0; i < m; i++) if (!is_pivot[i]) free_cols[fp++] = i;
    if (fp != bottom_dim) fail("bad free-coordinate count");

    mf3_e *a = mf3_alloc(top_dim, bottom_dim);
    for (size_t i = 0; i < top_dim; i++)
        for (size_t j = 0; j < bottom_dim; j++)
            mf3_setcoeff(a, i, j, mf3_coeff(u_rref, i, free_cols[j]));

    t0 = now_seconds();
    mf3_e *qnorm = mf3_alloc(param.n, bottom_dim);
    uint8_t *normalizer = malloc(param.n);
    hash_item *items = malloc(param.n * sizeof(*items));
    if (!normalizer || !items) fail("allocate quotient table");
    for (size_t col = 0; col < param.n; col++) {
        vf3_e *v = public_column(&pk, col);
        quotient(&qnorm->rows[col], v, a, pivots, free_cols);
        vf3_free(v);
        const size_t first = first_nonzero(&qnorm->rows[col]);
        if (first == SIZE_MAX) fail("zero quotient column");
        normalizer[col] = vf3_get_element(first, &qnorm->rows[col]);
        vf3_vector_scalarmul_nonzero_inplace(&qnorm->rows[col], normalizer[col]);
        items[col].hash = hash_vector(&qnorm->rows[col]);
        items[col].index = (uint32_t)col;
    }
    size_t candidate_quotient_matches = 0;
    for (size_t i = 0; i < candidate_count; i++) {
        if (vf3_equal(&qnorm->rows[candidates[i].a], &qnorm->rows[candidates[i].b]))
            candidate_quotient_matches++;
    }
    fprintf(stderr, "candidate_quotient_matches=%zu/%zu\n",
            candidate_quotient_matches, candidate_count);
    qsort(items, param.n, sizeof(*items), compare_hash_item);

    size_t *pair_a = malloc(pair_count * sizeof(*pair_a));
    size_t *pair_b = malloc(pair_count * sizeof(*pair_b));
    uint8_t *pair_rel = malloc(pair_count);
    uint8_t *hash_used = calloc(param.n, 1);
    if (!pair_a || !pair_b || !pair_rel || !hash_used) fail("allocate recovered pairs");
    size_t recovered = 0;
    for (size_t pos = 0; pos < param.n;) {
        size_t end = pos + 1;
        while (end < param.n && items[end].hash == items[pos].hash) end++;
        for (size_t p = pos; p < end; p++) {
            if (hash_used[p]) continue;
            const size_t ca = items[p].index;
            size_t match = SIZE_MAX, matches = 0;
            for (size_t q = p + 1; q < end; q++) {
                if (!hash_used[q] && vf3_equal(&qnorm->rows[ca], &qnorm->rows[items[q].index])) {
                    match = q;
                    matches++;
                }
            }
            if (matches != 1) {
                fprintf(stderr, "bad_quotient_multiplicity hash_class=%zu vector_matches=%zu\n",
                        end - pos, matches);
                fail("normalized quotient does not have a unique partner");
            }
            hash_used[p] = hash_used[match] = 1;
            const size_t cb = items[match].index;
            pair_a[recovered] = ca;
            pair_b[recovered] = cb;
            pair_rel[recovered] = (uint8_t)((3 - (normalizer[ca] * normalizer[cb]) % 3) % 3);
            if (!pair_rel[recovered]) fail("zero recovered relative scale");
            recovered++;
        }
        pos = end;
    }
    fprintf(stderr, "recovered_pairs=%zu/%zu quotient_elapsed=%.3f\n",
            recovered, pair_count, now_seconds() - t0);
    if (recovered != pair_count) fail("incomplete pairing");

    t0 = now_seconds();
    mf3_e *h_x = mf3_alloc(top_dim, pair_count);
    mf3_e *h_y = mf3_alloc(top_dim, pair_count);
    mf3_e *h_z = mf3_alloc(bottom_dim, pair_count);
    for (size_t i = 0; i < pair_count; i++) {
        const size_t ca = pair_a[i], cb = pair_b[i];
        const uint8_t rel = pair_rel[i];
        for (size_t r = 0; r < top_dim; r++) {
            mf3_setcoeff(h_x, r, i, public_coeff(&pk, pivots[r], ca));
            mf3_setcoeff(h_y, r, i, (uint8_t)(rel * public_coeff(&pk, pivots[r], cb) % 3));
        }
        for (size_t r = 0; r < bottom_dim; r++) {
            uint8_t qv = vf3_get_element(r, &qnorm->rows[ca]);
            qv = (uint8_t)(qv * normalizer[ca] % 3); /* undo normalization */
            mf3_setcoeff(h_z, r, i, qv ? (uint8_t)(3 - qv) : 0);
        }
    }
    mf3_e *h_xy = mf3_alloc(top_dim, pair_count);
    mf3_matrix_add(h_xy, h_x, h_y);
    fprintf(stderr, "equivalent_matrices_seconds=%.3f\n", now_seconds() - t0);

    uint8_t rng_seed[64];
    for (size_t i = 0; i < sizeof(rng_seed); i++) rng_seed[i] = (uint8_t)(0x31 + 13 * i);
    if (init_random_number(&drng_algorithm, rng_seed, sizeof(rng_seed))) fail("DRNG init");

    const uint8_t message[] = "fresh UVW-128 message forged from public transcripts";
    uvw_signature sig;
    sig.param = param;
    sig.r = malloc(param.lambda / 8);
    get_random_number(&drng_algorithm, sig.r, param.lambda);

    shake256_ctx hctx;
    uvw_hash_init(&hctx);
    uvw_hash_update(&hctx, message, sizeof(message) - 1);
    uvw_hash_update(&hctx, sig.r, param.lambda / 8);
    vf3_e *syndrome = NULL;
    hash_to_vf3(&hctx, &syndrome, m);
    uvw_hash_free(&hctx);

    vf3_e *s1 = vf3_alloc(top_dim);
    vf3_e *sfree = vf3_alloc(bottom_dim);
    vf3_e *sprod = vf3_alloc(bottom_dim);
    vf3_e *s2 = vf3_alloc(bottom_dim);
    split_coordinates(syndrome, pivots, top_dim, free_cols, bottom_dim, s1, sfree);
    mf3_product_vector_matrix(sprod, s1, a);
    vf3_vector_sub(s2, sfree, sprod);
    vf3_free(sfree);
    vf3_free(sprod);

    t0 = now_seconds();
    vf3_e *e2 = NULL;
    dec_z(h_z, s2, &e2);
    vf3_e *hye2 = vf3_alloc(top_dim);
    mf3_e *hyt = mf3_alloc(pair_count, top_dim);
    mf3_transpose_and_copy(hyt, h_y);
    mf3_product_vector_matrix(hye2, e2, hyt);
    mf3_free(hyt);
    vf3_e *s1prime = vf3_alloc(top_dim);
    vf3_vector_sub(s1prime, s1, hye2);
    vf3_free(hye2);
    vf3_e *e1 = NULL;
    dec_xy(h_xy, s1prime, e2, &e1, param.w);
    fprintf(stderr, "equivalent_decode_seconds=%.3f\n", now_seconds() - t0);

    vf3_e *e1e2 = vf3_alloc(pair_count);
    vf3_vector_add(e1e2, e1, e2);
    vf3_e *full = vf3_alloc(param.n);
    for (size_t i = 0; i < pair_count; i++) {
        vf3_set_coeff(pair_a[i], full, vf3_get_element(i, e1));
        vf3_set_coeff(pair_b[i], full,
                      (uint8_t)(pair_rel[i] * vf3_get_element(i, e1e2) % 3));
    }
    sig.e = vf3_alloc(param.k);
    vf3_e *left = vf3_alloc(m);
    vf3_vector_split(left, sig.e, full);

    shake256_ctx vctx;
    uvw_hash_init(&vctx);
    uvw_hash_update(&vctx, message, sizeof(message) - 1);
    const int accepted = uvw_verify(pk, &vctx, sig);
    uvw_hash_free(&vctx);

    const uint8_t control_message[] =
        "fresh UVW-128 message forged from public transcripts!";
    shake256_ctx control_ctx;
    uvw_hash_init(&control_ctx);
    uvw_hash_update(&control_ctx, control_message, sizeof(control_message) - 1);
    const int changed_message_accepted = uvw_verify(pk, &control_ctx, sig);
    uvw_hash_free(&control_ctx);

    size_t signature_bytes = 0;
    if (accepted && !changed_message_accepted)
        signature_bytes = write_api_signature(argv[4], &sig);
    printf("fresh_message_forgery_accepted=%d changed_message_rejected=%d "
           "signature_bytes=%zu weight=%zu\n",
           accepted, !changed_message_accepted, signature_bytes,
           vf3_hamming_weight(full));

    return accepted && !changed_message_accepted && signature_bytes == 1244 ? 0 : 1;
}

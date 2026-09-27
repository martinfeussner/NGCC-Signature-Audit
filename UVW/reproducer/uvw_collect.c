#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "drng.h"
#include "uvw.h"

DRNG_ctx drng_algorithm;

extern void hash_to_vf3(shake256_ctx *ctx, vf3_e **out, size_t len);
/* Added to a temporary copy of the submission by build.sh.  The private
 * object stays inside this signing-oracle driver and is never serialized. */
extern int uvw_reproducer_keygen(uvw_secret_key *out_sk, uvw_public_key *out_pk);

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

static void die(const char *what) {
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(1);
}

static void put_u32(FILE *f, uint32_t x) {
    uint8_t b[4] = {(uint8_t)x, (uint8_t)(x >> 8), (uint8_t)(x >> 16), (uint8_t)(x >> 24)};
    if (fwrite(b, 1, 4, f) != 4) die("write");
}

static int generate_worker(const uvw_keypair *kp, size_t start, size_t end,
                           const char *prefix, size_t worker) {
    const uvw_param param = kp->pk.param;
    uint8_t worker_seed[64];
    for (size_t i = 0; i < sizeof(worker_seed); i++)
        worker_seed[i] = (uint8_t)(0xa7u + 41u * i + 73u * worker);
    if (init_random_number(&drng_algorithm, worker_seed, sizeof(worker_seed))) return 1;

    char path[4096];
    snprintf(path, sizeof(path), "%s.part.%03zu.bin", prefix, worker);
    FILE *errors = fopen(path, "wb");
    if (!errors) return 1;

    mf3_e *rt = mf3_alloc(param.k, param.n - param.k);
    mf3_transpose_and_copy(rt, kp->pk.r);
    uint8_t *row = malloc(param.n);
    if (!row) return 1;

    const double sign_start = now_seconds();
    for (size_t sample = start; sample < end; sample++) {
        uint8_t msg[32] = {0};
        for (unsigned j = 0; j < 8; j++) msg[j] = (uint8_t)(sample >> (8u * j));
        for (unsigned j = 8; j < sizeof(msg); j++) msg[j] = (uint8_t)(j * 17u + sample * 3u);

        shake256_ctx sign_ctx;
        uvw_hash_init(&sign_ctx);
        uvw_hash_update(&sign_ctx, msg, sizeof(msg));
        uvw_signature sig = uvw_sign(kp->sk, &sign_ctx);
        uvw_hash_free(&sign_ctx);

        shake256_ctx hctx;
        uvw_hash_init(&hctx);
        uvw_hash_update(&hctx, msg, sizeof(msg));
        uvw_hash_update(&hctx, sig.r, param.lambda / 8);
        vf3_e *syndrome = NULL;
        hash_to_vf3(&hctx, &syndrome, param.n - param.k);
        uvw_hash_free(&hctx);

        vf3_e *product = vf3_alloc(param.n - param.k);
        vf3_e *left = vf3_alloc(param.n - param.k);
        mf3_product_vector_matrix(product, sig.e, rt);
        vf3_vector_sub(left, syndrome, product);
        vf3_free(product);
        vf3_free(syndrome);

        for (size_t i = 0; i < param.n - param.k; i++) row[i] = vf3_get_element(i, left);
        for (size_t i = 0; i < param.k; i++) row[param.n - param.k + i] = vf3_get_element(i, sig.e);
        if (fwrite(row, 1, param.n, errors) != param.n) return 1;

        const size_t left_w = vf3_hamming_weight(left);
        const size_t right_w = vf3_hamming_weight(sig.e);
        if (left_w + right_w != param.w) {
            fprintf(stderr, "worker=%zu invalid sample=%zu left=%zu right=%zu total=%zu\n",
                    worker, sample, left_w, right_w, left_w + right_w);
            return 1;
        }

        vf3_free(left);
        uvw_free_signature(sig);
        const size_t done = sample - start + 1;
        if (done % 10 == 0 || sample + 1 == end) {
            const double elapsed = now_seconds() - sign_start;
            fprintf(stderr, "worker=%zu signatures=%zu/%zu elapsed=%.3f rate=%.3f/s\n",
                    worker, done, end - start, elapsed, done / elapsed);
        }
    }

    fclose(errors);
    free(row);
    mf3_free(rt);
    return 0;
}

static void append_part(FILE *out, const char *path) {
    FILE *in = fopen(path, "rb");
    if (!in) die("open part");
    uint8_t buf[1 << 20];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), in)) != 0)
        if (fwrite(buf, 1, got, out) != got) die("append part");
    if (ferror(in)) die("read part");
    fclose(in);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s NSIG OUT_PREFIX WORKERS\n", argv[0]);
        return 2;
    }
    const size_t nsig = strtoull(argv[1], NULL, 10);
    size_t workers = strtoull(argv[3], NULL, 10);
    if (!nsig || nsig > UINT32_MAX) return 2;
    if (!workers) return 2;
    if (workers > nsig) workers = nsig;

    uint8_t seed[64];
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x53u + 29u * i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed))) {
        fprintf(stderr, "DRNG init failed\n");
        return 1;
    }

    const uvw_param param = uvw_param_from_level(1);
    double t0 = now_seconds();
    uvw_keypair kp;
    if (uvw_reproducer_keygen(&kp.sk, &kp.pk)) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    fprintf(stderr, "keygen_seconds=%.3f\n", now_seconds() - t0);

    char path[4096];

    snprintf(path, sizeof(path), "%s.pk.bin", argv[2]);
    FILE *pk_file = fopen(path, "wb");
    if (!pk_file) die("open pk");
    uvw_write_public_key(kp.pk, pk_file);
    fclose(pk_file);

    fflush(NULL);
    pid_t *pids = calloc(workers, sizeof(*pids));
    if (!pids) die("calloc pids");
    for (size_t w = 0; w < workers; w++) {
        pids[w] = fork();
        if (pids[w] < 0) die("fork");
        if (pids[w] == 0) {
            const size_t start = nsig * w / workers;
            const size_t end = nsig * (w + 1) / workers;
            const int rc = generate_worker(&kp, start, end, argv[2], w);
            _exit(rc);
        }
    }

    int failed = 0;
    for (size_t w = 0; w < workers; w++) {
        int status = 0;
        if (waitpid(pids[w], &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) failed = 1;
    }
    free(pids);
    if (failed) {
        fprintf(stderr, "one or more signature workers failed\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s.errors.bin", argv[2]);
    FILE *errors = fopen(path, "wb");
    if (!errors) die("open errors");
    put_u32(errors, (uint32_t)nsig);
    put_u32(errors, (uint32_t)param.n);
    for (size_t w = 0; w < workers; w++) {
        char part[4096];
        snprintf(part, sizeof(part), "%s.part.%03zu.bin", argv[2], w);
        append_part(errors, part);
        unlink(part);
    }
    fclose(errors);

    uvw_free_secret_key(kp.sk);
    uvw_free_public_key(kp.pk);
    return 0;
}

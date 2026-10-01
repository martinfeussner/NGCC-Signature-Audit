#include "SIG_AlgorithmInstance.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    long n;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    *buf = malloc(n ? (size_t)n : 1u);
    if (!*buf || (n && fread(*buf, 1, (size_t)n, f) != (size_t)n)) {
        free(*buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *len = (size_t)n;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len && fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t **out, size_t *out_len) {
    const size_t n = strlen(s);
    if ((n & 1u) != 0) return -1;
    *out_len = n / 2u;
    *out = malloc(*out_len ? *out_len : 1u);
    if (!*out) return -1;
    for (size_t i = 0; i < *out_len; ++i) {
        const int hi = hexval((unsigned char)s[2u * i]);
        const int lo = hexval((unsigned char)s[2u * i + 1u]);
        if (hi < 0 || lo < 0) {
            free(*out);
            *out = NULL;
            return -1;
        }
        (*out)[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int cmd_keygen(int argc, char **argv) {
    uint8_t *seed = NULL, *pk = NULL, *sk = NULL;
    size_t seed_len = 0;
    unsigned long long pk_len = 0, sk_len = 0;
    int rc = 1;
    if (argc != 5 || parse_hex(argv[2], &seed, &seed_len) != 0) return 2;
    pk = malloc((size_t)sig_get_pk_len_bytes());
    sk = malloc((size_t)sig_get_sk_len_bytes());
    if (!pk || !sk) goto out;
    galas_set_kat_seed(seed, (unsigned long long)seed_len);
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) goto out;
    if (write_file(argv[3], pk, (size_t)pk_len) != 0 ||
        write_file(argv[4], sk, (size_t)sk_len) != 0) goto out;
    printf("pristine_keygen=ok pk_bytes=%llu cached_sk_bytes=%llu\n", pk_len, sk_len);
    rc = 0;
out:
    free(seed); free(pk); free(sk);
    return rc;
}

static int sign_with_cached_key(const uint8_t *sk, size_t sk_len,
                                const char *msg_path, const char *sig_path) {
    uint8_t *msg = NULL, *sig = NULL;
    size_t msg_len = 0;
    unsigned long long sig_len = 0;
    int s_rc, rc = 1;
    if (read_file(msg_path, &msg, &msg_len) != 0) goto out;
    sig = malloc((size_t)sig_get_sn_len_bytes());
    if (!sig) goto out;
    s_rc = sig_sign((unsigned char *)sk, (unsigned long long)sk_len,
                    msg, (unsigned long long)msg_len, sig, &sig_len);
    if (s_rc != 0) {
        fprintf(stderr, "pristine_sign=reject rc=%d\n", s_rc);
        rc = 3;
        goto out;
    }
    if (write_file(sig_path, sig, (size_t)sig_len) != 0) goto out;
    printf("pristine_sign=ok sig_bytes=%llu\n", sig_len);
    rc = 0;
out:
    free(msg); free(sig);
    return rc;
}

static int cmd_sign(int argc, char **argv) {
    uint8_t *sk = NULL;
    size_t sk_len = 0;
    int rc = 1;
    if (argc != 5 || read_file(argv[2], &sk, &sk_len) != 0) goto out;
    rc = sign_with_cached_key(sk, sk_len, argv[3], argv[4]);
out:
    free(sk);
    return rc;
}

/* The submitted wrapper serializes sk as x||k, while the PDF serializes k.
 * This adapter performs only that documented interface conversion, then calls
 * the untouched submitted sig_sign function. */
static int cmd_sign_norm(int argc, char **argv) {
    uint8_t *pk = NULL, *k = NULL, *cached = NULL;
    size_t pk_len = 0, k_len = 0;
    const size_t cached_len = (size_t)sig_get_sk_len_bytes();
    const size_t lb = cached_len / 2u;
    int rc = 1;
    if (argc != 6 || read_file(argv[2], &pk, &pk_len) != 0 ||
        read_file(argv[3], &k, &k_len) != 0) goto out;
    if (pk_len != 2u * lb || k_len != lb) {
        fprintf(stderr, "sign-norm=input-length-error pk=%zu k=%zu lb=%zu\n",
                pk_len, k_len, lb);
        rc = 2;
        goto out;
    }
    cached = malloc(cached_len);
    if (!cached) goto out;
    memcpy(cached, pk, lb);
    memcpy(cached + lb, k, lb);
    rc = sign_with_cached_key(cached, cached_len, argv[4], argv[5]);
out:
    free(pk); free(k); free(cached);
    return rc;
}

static int cmd_verify(int argc, char **argv) {
    uint8_t *pk = NULL, *msg = NULL, *sig = NULL;
    size_t pk_len = 0, msg_len = 0, sig_len = 0;
    int v_rc, rc = 1;
    if (argc != 5 || read_file(argv[2], &pk, &pk_len) != 0 ||
        read_file(argv[3], &msg, &msg_len) != 0 ||
        read_file(argv[4], &sig, &sig_len) != 0) goto out;
    v_rc = sig_verify(pk, (unsigned long long)pk_len,
                      sig, (unsigned long long)sig_len,
                      msg, (unsigned long long)msg_len);
    printf("pristine_verify=%s rc=%d\n", v_rc == 0 ? "accept" : "reject", v_rc);
    rc = v_rc == 0 ? 0 : 4;
out:
    free(pk); free(msg); free(sig);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s keygen SEEDHEX PK CACHED_SK | sign CACHED_SK MSG SIG | sign-norm PK K MSG SIG | verify PK MSG SIG\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "keygen") == 0) return cmd_keygen(argc, argv);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc, argv);
    if (strcmp(argv[1], "sign-norm") == 0) return cmd_sign_norm(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}

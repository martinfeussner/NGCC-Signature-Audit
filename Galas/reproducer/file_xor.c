#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    FILE *in = NULL, *out = NULL;
    uint8_t *buf = NULL;
    long n;
    char *end = NULL;
    unsigned long off;
    int rc = 1;
    if (argc != 4) {
        fprintf(stderr, "usage: %s INPUT BYTE_OFFSET OUTPUT\n", argv[0]);
        return 2;
    }
    errno = 0;
    off = strtoul(argv[2], &end, 0);
    if (errno || !end || *end) return 2;
    in = fopen(argv[1], "rb");
    if (!in || fseek(in, 0, SEEK_END) || (n = ftell(in)) < 0 ||
        fseek(in, 0, SEEK_SET) || off >= (unsigned long)n) goto out;
    buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, in) != (size_t)n) goto out;
    buf[off] ^= 1u;
    out = fopen(argv[3], "wb");
    if (!out || fwrite(buf, 1, (size_t)n, out) != (size_t)n) goto out;
    printf("mutate=ok offset=%lu xor=01 bytes=%ld\n", off, n);
    rc = 0;
out:
    if (in) fclose(in);
    if (out && fclose(out) != 0) rc = 1;
    free(buf);
    return rc;
}

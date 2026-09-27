/* Construct an equivalent MORNING-ATLAS-128 key and forge a fresh message. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

typedef struct {
  char magic[8];
  uint32_t n, k, kappa, public_key_bytes;
  uint64_t signatures;
  unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
} hint_header;

static int read_s1(const char *path, polyvecl *s1) {
  FILE *fp = fopen(path, "r");
  if (!fp) return -1;
  for (unsigned p = 0; p < L; ++p)
    for (unsigned j = 0; j < N; ++j) {
      int value;
      if (fscanf(fp, "%d", &value) != 1 || value < -(int)ETA || value > (int)ETA) {
        fclose(fp);
        return -1;
      }
      s1->vec[p].coeffs[j] = (uint32_t)(value + (int)Q) & (Q - 1);
    }
  return fclose(fp);
}

static int read_t0(const char *path, polyveck *t0) {
  FILE *fp = fopen(path, "r");
  if (!fp) return -1;
  for (unsigned p = 0; p < K; ++p)
    for (unsigned j = 0; j < N; ++j) {
      int value;
      if (fscanf(fp, "%d", &value) != 1 || value < -511 || value > 512) {
        fclose(fp);
        return -1;
      }
      t0->vec[p].coeffs[j] = (uint32_t)(value + (int)Q) & (Q - 1);
    }
  return fclose(fp);
}

static int write_file(const char *path, const unsigned char *data, size_t length) {
  FILE *fp = fopen(path, "wb");
  if (!fp) return -1;
  int ok = fwrite(data, 1, length, fp) == length && fclose(fp) == 0;
  return ok ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc != 7) {
    fprintf(stderr,
            "usage: %s hint_transcript recovered_s1.txt recovered_t0.txt "
            "message.bin signature.bin equivalent_sk.bin\n",
            argv[0]);
    return 64;
  }

  hint_header header;
  FILE *hf = fopen(argv[1], "rb");
  if (!hf || fread(&header, sizeof header, 1, hf) != 1 || fclose(hf) != 0 ||
      memcmp(header.magic, "ATLHNT1", 8) != 0 || header.n != N ||
      header.k != K || header.kappa != KAPPA ||
      header.public_key_bytes != CRYPTO_PUBLICKEYBYTES) {
    fputs("invalid hint transcript\n", stderr);
    return 2;
  }

  polyvecl s1;
  polyveck t0, t1;
  if (read_s1(argv[2], &s1) != 0 || read_t0(argv[3], &t0) != 0) {
    fputs("invalid recovered secret text\n", stderr);
    return 3;
  }

  FILE *mf = fopen(argv[4], "rb");
  if (!mf || fseek(mf, 0, SEEK_END) != 0) return 4;
  long message_length_long = ftell(mf);
  if (message_length_long <= 0 || fseek(mf, 0, SEEK_SET) != 0) return 4;
  size_t message_length = (size_t)message_length_long;
  unsigned char *message = malloc(message_length);
  unsigned char *verify_message = malloc(message_length);
  unsigned char *signature = calloc(CRYPTO_BYTES + message_length, 1);
  if (!message || !verify_message || !signature ||
      fread(message, 1, message_length, mf) != message_length || fclose(mf) != 0)
    return 5;
  memcpy(verify_message, message, message_length);

  unsigned char rho[SEEDBYTES], key[SEEDBYTES], tr[CRHBYTES];
  unsigned char equivalent_sk[CRYPTO_SECRETKEYBYTES];
  unpack_pk(rho, &t1, header.public_key);
  for (unsigned i = 0; i < SEEDBYTES; ++i)
    key[i] = (unsigned char)(0xa7 ^ (17 * i + 3));
  if (pseudoXOF(CRHBYTES * 8, header.public_key,
                CRYPTO_PUBLICKEYBYTES * 8, tr) != 0)
    return 6;
  pack_sk(equivalent_sk, rho, key, tr, &s1, &t0);

  unsigned long long signature_length = 0;
  if (sig_sign(equivalent_sk, CRYPTO_SECRETKEYBYTES, message, message_length,
               signature, &signature_length) != 0)
    return 7;
  if (signature_length != CRYPTO_BYTES + message_length) return 8;
  int verified = sig_verify(header.public_key, CRYPTO_PUBLICKEYBYTES,
                            signature, CRYPTO_BYTES,
                            verify_message, message_length);
  if (verified != 0) {
    fputs("fresh-message forgery did not verify\n", stderr);
    return 9;
  }
  if (write_file(argv[5], signature, CRYPTO_BYTES) != 0 ||
      write_file(argv[6], equivalent_sk, CRYPTO_SECRETKEYBYTES) != 0)
    return 10;

  printf("forgery_verified=true message_bytes=%zu signature_bytes=%u "
         "source_signatures=%llu signature_file=%s equivalent_key_file=%s\n",
         message_length, CRYPTO_BYTES,
         (unsigned long long)header.signatures, argv[5], argv[6]);
  free(signature);
  free(verify_message);
  free(message);
  return 0;
}

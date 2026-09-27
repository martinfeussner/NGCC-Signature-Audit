/* Verify a detached MORNING-ATLAS-128 signature and a changed-message control. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static unsigned char *read_file(const char *path, size_t *length) {
  FILE *stream = fopen(path, "rb");
  if (!stream || fseek(stream, 0, SEEK_END) != 0) return NULL;
  long end = ftell(stream);
  if (end < 0 || fseek(stream, 0, SEEK_SET) != 0) return NULL;
  unsigned char *data = malloc(end ? (size_t)end : 1);
  if (!data || fread(data, 1, (size_t)end, stream) != (size_t)end ||
      fclose(stream) != 0) {
    free(data);
    return NULL;
  }
  *length = (size_t)end;
  return data;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s public-key message signature\n", argv[0]);
    return 2;
  }
  size_t pk_len, message_len, signature_len;
  unsigned char *pk = read_file(argv[1], &pk_len);
  unsigned char *message = read_file(argv[2], &message_len);
  unsigned char *signature = read_file(argv[3], &signature_len);
  if (!pk || !message || !signature || pk_len != sig_get_pk_len_bytes() ||
      signature_len != CRYPTO_BYTES || message_len == 0) return 2;

  int accepted = sig_verify(pk, pk_len, signature, signature_len,
                            message, message_len) == 0;
  message[0] ^= 1;
  int changed = sig_verify(pk, pk_len, signature, signature_len,
                           message, message_len) == 0;
  printf("forgery=%s changed-message=%s\n",
         accepted ? "ACCEPTED" : "REJECTED",
         changed ? "ACCEPTED" : "REJECTED");
  free(signature);
  free(message);
  free(pk);
  return accepted && !changed ? 0 : 1;
}

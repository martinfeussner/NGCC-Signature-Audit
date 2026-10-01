#include "instances.h"
#include "voleith_impl.h"

#include <stdio.h>
#include <stdlib.h>

static unsigned char* read_all(const char* path, size_t want) {
  FILE* f = fopen(path, "rb");
  if (!f) return NULL;
  unsigned char* p = malloc(want ? want : 1);
  if (!p || fread(p, 1, want, f) != want || fgetc(f) != EOF || fclose(f) != 0) {
    free(p); return NULL;
  }
  return p;
}

int main(int argc, char** argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: %s level public-key message signature\n", argv[0]);
    return 2;
  }
  unsigned long level = strtoul(argv[1], NULL, 0);
  sig_paramid_t id = level == 160 ? RESOLVED_ALPHA_160S :
                     level == 256 ? RESOLVED_ALPHA_256S :
                     level == 384 ? RESOLVED_ALPHA_384S :
                     level == 512 ? RESOLVED_ALPHA_512S : PARAMETER_SET_INVALID;
  const sig_paramset_t* p = sig_get_paramset(id);
  if (!p) return 2;
  FILE* mf = fopen(argv[3], "rb");
  if (!mf) return 2;
  if (fseek(mf, 0, SEEK_END) != 0) return 2;
  long mlen_l = ftell(mf);
  if (mlen_l < 0 || fseek(mf, 0, SEEK_SET) != 0) return 2;
  size_t mlen = (size_t)mlen_l;
  unsigned char* msg = malloc(mlen ? mlen : 1);
  if (!msg || fread(msg, 1, mlen, mf) != mlen || fclose(mf) != 0) return 2;
  unsigned char* pk = read_all(argv[2], p->owf_input_size + p->owf_output_size);
  unsigned char* sig = read_all(argv[4], p->sig_size);
  if (!pk || !sig) return 2;
  int rc = voleith_verify(msg, mlen, sig, pk, pk + p->owf_input_size, p);
  printf("level=%lu pk=%s message=%s signature=%s untouched_submitted_verifier_rc=%d\n",
         level, argv[2], argv[3], argv[4], rc);
  free(sig); free(pk); free(msg);
  return rc == 0 ? 0 : 1;
}

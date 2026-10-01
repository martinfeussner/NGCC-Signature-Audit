/* Generate a same-key, same-message deterministic S/F query pair.
 *
 * This program is test-fixture code, not part of the attack.  The signing
 * calls use the submitted reference core after the single documented
 * CoinHash conformance repair: CoinHash absorbs seed_pk || seed_sk.  The
 * recovered-witness program is a separate process and receives none of the
 * values retained here for key generation.
 */

#include "instances.h"
#include "rsd.h"
#include "voleith_impl.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static sig_paramid_t param_id(unsigned int level, int fast) {
  switch (level) {
    case 160: return fast ? RESOLVED_ALPHA_160F : RESOLVED_ALPHA_160S;
    case 256: return fast ? RESOLVED_ALPHA_256F : RESOLVED_ALPHA_256S;
    case 384: return fast ? RESOLVED_ALPHA_384F : RESOLVED_ALPHA_384S;
    case 512: return fast ? RESOLVED_ALPHA_512F : RESOLVED_ALPHA_512S;
    default: return PARAMETER_SET_INVALID;
  }
}

static uint8_t* read_message(const char* path, size_t* len) {
  FILE* f = fopen(path, "rb");
  if (!f || fseek(f, 0, SEEK_END) != 0) return NULL;
  const long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
  *len = (size_t)n;
  uint8_t* p = malloc(*len ? *len : 1);
  if (!p || fread(p, 1, *len, f) != *len || fclose(f) != 0) {
    free(p); return NULL;
  }
  return p;
}

static int write_file(const char* dir, const char* name,
                      const uint8_t* p, size_t len) {
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) return -1;
  FILE* f = fopen(path, "wb");
  if (!f) return -1;
  return fwrite(p, 1, len, f) == len && fclose(f) == 0 ? 0 : -1;
}

int main(int argc, char** argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s LEVEL QUERY_MESSAGE OTHER_MESSAGE OUTDIR full|positive\n", argv[0]);
    return 2;
  }
  const unsigned int level = (unsigned int)strtoul(argv[1], NULL, 0);
  const sig_paramset_t* ps = sig_get_paramset(param_id(level, 0));
  const sig_paramset_t* pf = sig_get_paramset(param_id(level, 1));
  if (!ps || !pf) return 2;
  const int full_controls = strcmp(argv[5], "full") == 0;
  if (!full_controls && strcmp(argv[5], "positive") != 0) return 2;
  if (mkdir(argv[4], 0775) != 0 && errno != EEXIST) return 2;

  size_t qlen = 0, olen = 0;
  uint8_t* query = read_message(argv[2], &qlen);
  uint8_t* other = read_message(argv[3], &olen);
  if (!query || !other) return 2;

  const size_t lb = ps->csp / 8;
  const size_t pklen = ps->owf_input_size + ps->owf_output_size;
  const size_t wb = (ps->lenwit + 7) / 8;
  uint8_t seed_pk[MAX_CSP_BYTES], seed_sk[MAX_CSP_BYTES];
  uint8_t seed_pk_alt[MAX_CSP_BYTES], seed_sk_alt[MAX_CSP_BYTES];
  uint8_t rho0[MAX_CSP_BYTES] = {0}, rho1[MAX_CSP_BYTES];
  for (size_t i = 0; i < lb; ++i) {
    seed_pk[i] = (uint8_t)(0x10 + 7 * i + level);
    seed_sk[i] = (uint8_t)(0xa3 ^ (13 * i) ^ level);
    seed_pk_alt[i] = (uint8_t)(0xe1 - 3 * i + level);
    seed_sk_alt[i] = (uint8_t)(0x59 + 11 * i + level);
    rho1[i] = (uint8_t)(0x80 + i + level);
  }

  uint8_t* pk = calloc(pklen, 1);
  uint8_t* pk_alt = calloc(pklen, 1);
  uint8_t* witness = calloc(wb, 1);
  uint8_t* witness_alt = calloc(wb, 1);
  uint8_t* sig_s = calloc(ps->sig_size, 1);
  uint8_t* sig_f = calloc(pf->sig_size, 1);
  uint8_t* sig_s_other = calloc(ps->sig_size, 1);
  uint8_t* sig_s_rho = calloc(ps->sig_size, 1);
  uint8_t* sig_s_key = calloc(ps->sig_size, 1);
  if (!pk || !pk_alt || !witness || !witness_alt || !sig_s || !sig_f ||
      !sig_s_other || !sig_s_rho || !sig_s_key) abort();

  memcpy(pk, seed_pk, ps->owf_input_size);
  memcpy(pk_alt, seed_pk_alt, ps->owf_input_size);
  rsd_owf(seed_sk, seed_pk, pk + ps->owf_input_size, ps);
  rsd_owf(seed_sk_alt, seed_pk_alt, pk_alt + ps->owf_input_size, ps);
  rsd_extend_witness(witness, seed_sk, seed_pk, ps);
  rsd_extend_witness(witness_alt, seed_sk_alt, seed_pk_alt, ps);

  voleith_sign(sig_s, query, qlen, seed_sk, seed_pk,
               pk + ps->owf_input_size, witness, rho0, lb, ps);
  voleith_sign(sig_f, query, qlen, seed_sk, seed_pk,
               pk + pf->owf_input_size, witness, rho0, lb, pf);
  if (full_controls) {
    voleith_sign(sig_s_other, other, olen, seed_sk, seed_pk,
                 pk + ps->owf_input_size, witness, rho0, lb, ps);
    voleith_sign(sig_s_rho, query, qlen, seed_sk, seed_pk,
                 pk + ps->owf_input_size, witness, rho1, lb, ps);
    voleith_sign(sig_s_key, query, qlen, seed_sk_alt, seed_pk_alt,
                 pk_alt + ps->owf_input_size, witness_alt, rho0, lb, ps);
  }

  const int vs = voleith_verify(query, qlen, sig_s, pk,
                                pk + ps->owf_input_size, ps);
  const int vf = voleith_verify(query, qlen, sig_f, pk,
                                pk + pf->owf_input_size, pf);
  int io = 0;
  io |= write_file(argv[4], "public-key.bin", pk, pklen);
  io |= write_file(argv[4], "honest-s.sig", sig_s, ps->sig_size);
  io |= write_file(argv[4], "honest-f.sig", sig_f, pf->sig_size);
  if (full_controls) {
    io |= write_file(argv[4], "public-key-alt.bin", pk_alt, pklen);
    io |= write_file(argv[4], "different-message-s.sig", sig_s_other, ps->sig_size);
    io |= write_file(argv[4], "different-rho-s.sig", sig_s_rho, ps->sig_size);
    io |= write_file(argv[4], "different-key-s.sig", sig_s_key, ps->sig_size);
  }

  printf("{\"level\":%u,\"honest_s_rc\":%d,\"honest_f_rc\":%d,"
         "\"deterministic_rho\":\"all-zero\",\"full_controls\":%s,"
         "\"artifact_io\":%d}\n",
         level, vs, vf, full_controls ? "true" : "false", io);

  free(sig_s_key); free(sig_s_rho); free(sig_s_other); free(sig_f); free(sig_s);
  free(witness_alt); free(witness); free(pk_alt); free(pk); free(other); free(query);
  return vs == 0 && vf == 0 && io == 0 ? 0 : 1;
}

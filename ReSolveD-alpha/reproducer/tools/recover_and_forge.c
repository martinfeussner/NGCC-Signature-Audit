/* Independent public-input implementation of ReSolveD-alpha S/F recovery.
 *
 * This file independently parses the signatures, reconstructs their public
 * openings, derives an F hidden leaf from a parent reconstructed through S,
 * rebuilds u_a, and checks the recovered RSD witness against the public key.
 * It links submitted primitives and the prover from the spec-core build, whose
 * sole conformance repair makes CoinHash absorb the complete secret key.  The
 * fresh signature uses that conformance-repaired prover with attacker-chosen
 * proof coins.  Final acceptance is tested separately by untouched_verify,
 * which links to the byte-for-byte submitted cryptographic core.
 */

#include "instances.h"
#include "prg.h"
#include "rsd.h"
#include "tccr.h"
#include "utils.h"
#include "voleith_impl.h"
#include "xof.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NODE(buf, idx, lb) ((buf) + (size_t)(idx) * (lb))

static size_t ell_hat_bytes(const sig_paramset_t* p) {
  return (p->lenwit + 2 * p->csp + UNIVERSAL_HASH_B_BITS + 7) / 8;
}
static size_t witness_bytes(const sig_paramset_t* p) { return (p->lenwit + 7) / 8; }
static const uint8_t* sig_c(const uint8_t* sig, unsigned int stored_index,
                            const sig_paramset_t* p) {
  return sig + (size_t)stored_index * ell_hat_bytes(p);
}
static const uint8_t* sig_d(const uint8_t* sig, const sig_paramset_t* p) {
  return sig + (size_t)(p->tau - 1) * ell_hat_bytes(p) + p->csp / 8 + UNIVERSAL_HASH_B;
}
static const uint8_t* sig_decom(const uint8_t* sig, const sig_paramset_t* p) {
  return sig_d(sig, p) + witness_bytes(p) + p->csp / 8;
}
static const uint8_t* sig_chall3(const uint8_t* sig, const sig_paramset_t* p) {
  return sig + p->sig_size - 4 - IV_SIZE - p->csp / 8;
}
static const uint8_t* sig_iv(const uint8_t* sig, const sig_paramset_t* p) {
  return sig + p->sig_size - 4 - IV_SIZE;
}

/* Exact zero-based equivalent of submitted BAVC.PosInTree. */
static unsigned int pos_in_tree(unsigned int a, unsigned int j,
                                const sig_paramset_t* p) {
  const unsigned int half = 1u << (p->k - 1);
  if (j < half) return p->L - 1 + p->tau * j + a;
  return p->L - 1 + p->tau * half + p->tau1 * (j & (half - 1)) + a;
}

static void derive_s(uint8_t* s, const uint8_t* pk, const uint8_t* msg,
                     size_t msglen, const sig_paramset_t* p) {
  const uint8_t domain = 0;
  const size_t lb = p->csp / 8;
  uint8_t out[3 * MAX_CSP_BYTES];
  hash_context ctx;
  hash_init(&ctx, p->csp);
  hash_update(&ctx, &domain, 1);
  hash_update(&ctx, pk, p->owf_input_size + p->owf_output_size);
  hash_update(&ctx, msg, msglen);
  hash_final(&ctx);
  hash_squeeze(&ctx, out, 3 * lb);
  hash_clear(&ctx);
  memcpy(s, out + 2 * lb, lb);
}

static void expand_node(uint8_t* keys, unsigned int parent0, const uint8_t* iv,
                        const uint8_t* s, const sig_paramset_t* p) {
  const size_t lb = p->csp / 8;
  const unsigned int id1 = parent0 + 1;
  uint8_t* parent = NODE(keys, parent0, lb);
  uint8_t* left = NODE(keys, 2 * parent0 + 1, lb);
  uint8_t* right = NODE(keys, 2 * parent0 + 2, lb);
  if (id1 < p->L / 2) {
    tccr_hash(parent, s, iv, left, p->csp);
    xor_u8_array(left, parent, right, lb);
  } else {
    tccr_hash_x0_x1(parent, s, iv, left, right, p->csp);
  }
}

/* Reimplement submitted reconstruct_keys.  marked=1 means a hidden-leaf
 * ancestor and therefore unavailable from this opening. */
static bool reconstruct_opening(uint8_t** keys_out, uint8_t** marked_out,
                                uint16_t* delta_out, const uint8_t* sig,
                                const uint8_t* s, const sig_paramset_t* p) {
  const size_t lb = p->csp / 8;
  const size_t nodes_count = 2u * p->L - 1;
  uint8_t* marked = calloc((nodes_count + 7) / 8, 1);
  uint8_t* keys = calloc(nodes_count, lb);
  if (!marked || !keys || !decode_all_chall_3(delta_out, sig_chall3(sig, p), p)) {
    free(keys); free(marked); return false;
  }
  for (unsigned int a = 0; a < p->tau; ++a)
    ptr_set_bit(marked, pos_in_tree(a, delta_out[a], p), 1);

  const uint8_t* serialized = sig_decom(sig, p) + 2u * p->tau * lb;
  const uint8_t* end = serialized + (size_t)p->T_open * lb;
  for (int parent = (int)p->L - 2; parent >= 0; --parent) {
    const unsigned int left = 2u * (unsigned int)parent + 1;
    const unsigned int right = left + 1;
    const unsigned int ml = ptr_get_bit(marked, left);
    const unsigned int mr = ptr_get_bit(marked, right);
    ptr_set_bit(marked, (unsigned int)parent, ml | mr);
    if ((ml ^ mr) != 0) {
      if (serialized + lb > end) { free(keys); free(marked); return false; }
      const unsigned int exposed_child = ml ? right : left;
      memcpy(NODE(keys, exposed_child, lb), serialized, lb);
      serialized += lb;
    }
  }
  while (serialized != end) {
    if (*serialized++) { free(keys); free(marked); return false; }
  }
  for (unsigned int parent = 0; parent < p->L - 1; ++parent)
    if (!ptr_get_bit(marked, parent)) expand_node(keys, parent, sig_iv(sig, p), s, p);

  *keys_out = keys;
  *marked_out = marked;
  return true;
}

static bool public_relation(const uint8_t* w, const uint8_t* pk,
                            const sig_paramset_t* p, bool* padding_zero) {
  const unsigned int n = p->rsd_code_length;
  const unsigned int k = p->rsd_dimension;
  const unsigned int rows = n - k;
  const unsigned int b_blocks = k / 6;
  uint8_t* e = calloc((n + 7) / 8, 1);
  uint8_t* hb = rsd_sample_matrix_b(pk, p);
  if (!e || !hb) abort();

  for (unsigned int b = 0; b < b_blocks; ++b) {
    uint8_t last = 1;
    for (unsigned int j = 0; j < 5; ++j) {
      const uint8_t bit = ptr_get_bit(w, 5 * b + j);
      ptr_set_bit(e, rows + 6 * b + j, bit);
      last ^= bit;
    }
    ptr_set_bit(e, rows + 6 * b + 5, last);
  }
  for (unsigned int r = 0; r < rows; ++r) {
    uint8_t bit = ptr_get_bit(pk + p->owf_input_size, r);
    for (unsigned int c = 0; c < k; ++c)
      bit ^= ptr_get_bit(hb, (size_t)r * k + c) & ptr_get_bit(e, rows + c);
    ptr_set_bit(e, r, bit);
  }
  bool ok = true;
  for (unsigned int b = 0; b < p->rsd_noise_weight; ++b) {
    unsigned int weight = 0;
    for (unsigned int j = 0; j < 6; ++j) weight += ptr_get_bit(e, 6 * b + j);
    ok &= (weight == 1);
  }
  *padding_zero = true;
  for (unsigned int bit = p->rsd_witness_bits; bit < 8 * witness_bytes(p); ++bit)
    *padding_zero &= ptr_get_bit(w, bit) == 0;
  free(hb); free(e);
  return ok;
}

static uint8_t* read_exact(const char* path, size_t len) {
  FILE* f = fopen(path, "rb");
  uint8_t* p = malloc(len ? len : 1);
  if (!f || !p || fread(p, 1, len, f) != len || fgetc(f) != EOF) {
    if (f) fclose(f);
    free(p);
    return NULL;
  }
  if (fclose(f) != 0) { free(p); return NULL; }
  return p;
}
static uint8_t* read_message(const char* path, size_t* len) {
  FILE* f = fopen(path, "rb");
  if (!f || fseek(f, 0, SEEK_END)) return NULL;
  const long n = ftell(f);
  if (n < 0 || fseek(f, 0, SEEK_SET)) { fclose(f); return NULL; }
  *len = (size_t)n;
  uint8_t* p = malloc(*len ? *len : 1);
  if (!p || fread(p, 1, *len, f) != *len || fclose(f) != 0) { free(p); return NULL; }
  return p;
}
static bool write_exact(const char* path, const uint8_t* p, size_t len) {
  FILE* f = fopen(path, "wb");
  if (!f) return false;
  return fwrite(p, 1, len, f) == len && fclose(f) == 0;
}

static sig_paramid_t param_id(unsigned int level, bool fast) {
  switch (level) {
    case 160: return fast ? RESOLVED_ALPHA_160F : RESOLVED_ALPHA_160S;
    case 256: return fast ? RESOLVED_ALPHA_256F : RESOLVED_ALPHA_256S;
    case 384: return fast ? RESOLVED_ALPHA_384F : RESOLVED_ALPHA_384S;
    case 512: return fast ? RESOLVED_ALPHA_512F : RESOLVED_ALPHA_512S;
    default: return PARAMETER_SET_INVALID;
  }
}

int main(int argc, char** argv) {
  if (argc != 9) {
    fprintf(stderr, "usage: %s LEVEL PK QUERY_MSG SIG_S SIG_F FRESH_MSG OUT_W OUT_SIG\n", argv[0]);
    return 2;
  }
  const unsigned int level = (unsigned int)strtoul(argv[1], NULL, 0);
  const sig_paramset_t* ps = sig_get_paramset(param_id(level, false));
  const sig_paramset_t* pf = sig_get_paramset(param_id(level, true));
  if (!ps || !pf) return 2;
  const size_t pklen = ps->owf_input_size + ps->owf_output_size;
  const size_t lb = ps->csp / 8, wb = witness_bytes(ps), ehb = ell_hat_bytes(pf);
  size_t qlen = 0, fresh_len = 0;
  uint8_t* pk = read_exact(argv[2], pklen);
  uint8_t* query = read_message(argv[3], &qlen);
  uint8_t* ss = read_exact(argv[4], ps->sig_size);
  uint8_t* sf = read_exact(argv[5], pf->sig_size);
  uint8_t* fresh = read_message(argv[6], &fresh_len);
  if (!pk || !query || !ss || !sf || !fresh) return 2;

  const int honest_s = voleith_verify(query, qlen, ss, pk, pk + ps->owf_input_size, ps);
  const int honest_f = voleith_verify(query, qlen, sf, pk, pk + pf->owf_input_size, pf);
  uint8_t salt_s[MAX_CSP_BYTES], salt_f[MAX_CSP_BYTES];
  derive_s(salt_s, pk, query, qlen, ps);
  derive_s(salt_f, pk, query, qlen, pf);
  const bool salt_equal = memcmp(salt_s, salt_f, lb) == 0;
  const bool iv_equal = memcmp(sig_iv(ss, ps), sig_iv(sf, pf), IV_SIZE) == 0;

  uint16_t ds[MAX_TAU], df[MAX_TAU];
  uint8_t *skeys = NULL, *smarked = NULL, *fkeys = NULL, *fmarked = NULL;
  bool structures = reconstruct_opening(&skeys, &smarked, ds, ss, salt_s, ps) &&
                    reconstruct_opening(&fkeys, &fmarked, df, sf, salt_f, pf);
  uint8_t* u_a = calloc(ehb, 1);
  uint8_t* block = malloc(ehb);
  uint8_t* w = calloc(wb, 1);
  uint8_t* forgery = calloc(ps->sig_size, 1);
  if (!u_a || !block || !w || !forgery) abort();
  bool recovered = false;
  unsigned int used = pf->tau;
  unsigned int recoverable_count = 0;
  unsigned int unique_f_parents = 0;
  bool f_alone_parents_blocked = structures;
  if (structures) {
    unsigned int seen[MAX_TAU];
    for (unsigned int a = 0; a < pf->tau; ++a) {
      const unsigned int parent = (pos_in_tree(a, df[a], pf) - 1) / 2;
      f_alone_parents_blocked &= ptr_get_bit(fmarked, parent) != 0;
      bool duplicate = false;
      for (unsigned int i = 0; i < unique_f_parents; ++i) duplicate |= seen[i] == parent;
      if (!duplicate) seen[unique_f_parents++] = parent;
    }
  }
  if (honest_s == 0 && honest_f == 0 && salt_equal && iv_equal && structures) {
    for (unsigned int a = 0; a < pf->tau; ++a) {
      const unsigned int hidden_leaf = pos_in_tree(a, df[a], pf);
      const unsigned int parent = (hidden_leaf - 1) / 2;
      if (ptr_get_bit(smarked, parent)) continue;
      ++recoverable_count;
      if (recovered) continue;

      uint8_t left[MAX_CSP_BYTES], right[MAX_CSP_BYTES];
      /* In one-based specification indices this must be an F bottom parent and
       * an S upper-region node. */
      if (parent + 1 < pf->L / 2 || parent + 1 >= ps->L / 2) continue;
      tccr_hash_x0_x1(NODE(skeys, parent, lb), salt_f, sig_iv(sf, pf),
                      left, right, pf->csp);
      const uint8_t* hidden_seed =
          hidden_leaf == 2 * parent + 1 ? left : right;

      memset(u_a, 0, ehb);
      const unsigned int nleaves = 1u << (a < pf->tau1 ? pf->k : pf->k - 1);
      const uint8_t tweak = (uint8_t)((2 * pf->csp + 127) / 128);
      bool complete = true;
      for (unsigned int j = 0; j < nleaves; ++j) {
        const unsigned int node = pos_in_tree(a, j, pf);
        const uint8_t* seed = NULL;
        if (j == df[a]) seed = hidden_seed;
        else if (!ptr_get_bit(fmarked, node)) seed = NODE(fkeys, node, lb);
        else { complete = false; break; }
        prg(seed, sig_iv(sf, pf), tweak, block, pf->csp, ehb);
        xor_u8_array(u_a, block, u_a, ehb);
      }
      if (!complete) continue;
      if (a > 0) xor_u8_array(u_a, sig_c(sf, a - 1, pf), u_a, ehb);
      xor_u8_array(sig_d(sf, pf), u_a, w, wb);
      used = a;
      recovered = true;
    }
  }

  bool padding_zero = false;
  const bool relation = recovered && public_relation(w, pk, ps, &padding_zero);
  int forged_rc = -99, wrong_rc = -99, mutated_rc = -99;
  bool wrote_w = false, wrote_sig = false;
  if (relation && padding_zero) {
    uint8_t aux[MAX_CSP_BYTES], rho[MAX_CSP_BYTES];
    for (size_t i = 0; i < lb; ++i) { aux[i] = (uint8_t)(0x91 + 13 * i); rho[i] = (uint8_t)(0x37 ^ i); }
    voleith_sign(forgery, fresh, fresh_len, aux, pk, pk + ps->owf_input_size,
                 w, rho, lb, ps);
    forged_rc = voleith_verify(fresh, fresh_len, forgery, pk,
                               pk + ps->owf_input_size, ps);
    wrong_rc = voleith_verify(query, qlen, forgery, pk,
                              pk + ps->owf_input_size, ps);
    uint8_t* bad = malloc(wb);
    uint8_t* badsig = calloc(ps->sig_size, 1);
    if (!bad || !badsig) abort();
    memcpy(bad, w, wb); bad[0] ^= 1;
    voleith_sign(badsig, fresh, fresh_len, aux, pk, pk + ps->owf_input_size,
                 bad, rho, lb, ps);
    mutated_rc = voleith_verify(fresh, fresh_len, badsig, pk,
                                pk + ps->owf_input_size, ps);
    free(badsig); free(bad);
    wrote_w = write_exact(argv[7], w, wb);
    wrote_sig = write_exact(argv[8], forgery, ps->sig_size);
  }

  printf("{\"level\":%u,\"honest_s\":%d,\"honest_f\":%d,"
         "\"salt_equal\":%s,\"iv_equal\":%s,\"structures\":%s,"
         "\"f_alone_parents_blocked\":%s,\"unique_f_parents\":%u,"
         "\"recoverable_instances\":%u,\"used_instance\":%u,"
         "\"recovered\":%s,\"public_relation\":%s,\"padding_zero\":%s,"
         "\"fresh_forgery_rc\":%d,\"wrong_message_rc\":%d,"
         "\"mutated_witness_rc\":%d,\"wrote_witness\":%s,\"wrote_forgery\":%s}\n",
         level, honest_s, honest_f, salt_equal ? "true" : "false",
         iv_equal ? "true" : "false", structures ? "true" : "false",
         f_alone_parents_blocked ? "true" : "false", unique_f_parents,
         recoverable_count, used, recovered ? "true" : "false",
         relation ? "true" : "false", padding_zero ? "true" : "false",
         forged_rc, wrong_rc, mutated_rc, wrote_w ? "true" : "false",
         wrote_sig ? "true" : "false");

  const bool pass = honest_s == 0 && honest_f == 0 && salt_equal && iv_equal &&
                    structures && f_alone_parents_blocked && recoverable_count > 0 &&
                    relation && padding_zero &&
                    forged_rc == 0 && wrong_rc != 0 && mutated_rc != 0 && wrote_w && wrote_sig;
  free(forgery); free(w); free(block); free(u_a);
  free(fmarked); free(fkeys); free(smarked); free(skeys);
  free(fresh); free(sf); free(ss); free(query); free(pk);
  return pass ? 0 : 1;
}

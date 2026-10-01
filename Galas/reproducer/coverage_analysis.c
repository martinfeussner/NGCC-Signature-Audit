#include "instances.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>

static uint32_t pos_in_tree(unsigned i, unsigned j, const galas_paramset_t *ps) {
    uint32_t short_len = 1u << (ps->p.k - 1u);
    if (j < short_len) return ps->p.L - 1u + (uint32_t)ps->p.tau * j + i;
    return ps->p.L - 1u + (uint32_t)ps->p.tau * short_len +
           (uint32_t)ps->p.tau1 * (j & (short_len - 1u)) + i;
}

static int is_ancestor(uint32_t ancestor, uint32_t node) {
    while (node > ancestor) node = (node - 1u) / 2u;
    return node == ancestor;
}

static void analyze(galas_instance_id_t sid, galas_instance_id_t fid,
                    const char *label) {
    const galas_paramset_t *s = galas_get_paramset(sid);
    const galas_paramset_t *f = galas_get_paramset(fid);
    unsigned nf = galas_bavc_leaves(0, f);
    long double psum = 0.0L, pmin = 1.0L, pmax = 0.0L;
    unsigned always = 0;
    for (unsigned jf = 0; jf < nf; ++jf) {
        uint32_t alpha = pos_in_tree(0, jf, f);
        long double p = 1.0L;
        for (unsigned i = 0; i < s->p.tau; ++i) {
            unsigned ni = galas_bavc_leaves(i, s), under = 0;
            for (unsigned js = 0; js < ni; ++js)
                under += (unsigned)is_ancestor(alpha, pos_in_tree(i, js, s));
            p *= 1.0L - (long double)under / (long double)ni;
        }
        psum += p;
        if (p < pmin) pmin = p;
        if (p > pmax) pmax = p;
        if (p == 1.0L) ++always;
    }
    printf("lambda=%s S_L=%u F_L=%u F_tree0_leaves=%u unconditioned_model_success=%.12Lf min=%.12Lf max=%.12Lf always=%u\n",
           label, s->p.L, f->p.L, nf, psum / (long double)nf,
           pmin, pmax, always);
}

int main(void) {
    analyze(GALAS_160S, GALAS_160F, "160");
    analyze(GALAS_256S, GALAS_256F, "256");
    analyze(GALAS_384S, GALAS_384F, "384");
    analyze(GALAS_512S, GALAS_512F, "512");
    return 0;
}

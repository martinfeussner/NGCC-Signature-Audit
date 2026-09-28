#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cs.h>

static double log_pmf[2 * bound0 + 1];
static double complex twist[n];

static void init_pmf(void) {
    uint64_t cur[5 * 31 + 1] = {0}, next[5 * 31 + 1] = {0};
    int max = 0;
    cur[0] = 1;
    for (int r = 0; r < 5; r++) {
        memset(next, 0, sizeof(next));
        for (int s = 0; s <= max; s++)
            for (int u = 0; u < 32; u++) next[s + u] += cur[s];
        max += 31;
        memcpy(cur, next, sizeof(cur));
    }
    for (int d = -bound0; d <= bound0; d++) {
        uint64_t v = 0;
        for (int s = 0; s <= max; s++) {
            int t = s - d;
            if (t >= 0 && t <= max) v += cur[s] * cur[t];
        }
        log_pmf[d + bound0] = log((double)v);
    }
    for (int j = 0; j < n; j++)
        twist[j] = cexp(-I * M_PI * (double)j / (double)n);
}

static void fft(double complex a[n], int inverse) {
    for (unsigned i = 1, j = 0; i < n; i++) {
        unsigned bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) { double complex t = a[i]; a[i] = a[j]; a[j] = t; }
    }
    for (unsigned len = 2; len <= n; len <<= 1) {
        double ang = (inverse ? 2.0 : -2.0) * M_PI / (double)len;
        double complex wl = cexp(I * ang);
        for (unsigned i = 0; i < n; i += len) {
            double complex w = 1.0;
            for (unsigned j = 0; j < len / 2; j++) {
                double complex u = a[i + j], v = a[i + j + len / 2] * w;
                a[i + j] = u + v;
                a[i + j + len / 2] = u - v;
                w *= wl;
            }
        }
    }
    if (inverse) for (int i = 0; i < n; i++) a[i] /= (double)n;
}

static void negacyclic_fft_i32(double complex out[n], const int32_t in[n]) {
    for (int j = 0; j < n; j++) out[j] = (double)in[j] * twist[j];
    fft(out, 0);
}

static void negacyclic_fft_double(double complex out[n], const double in[n]) {
    for (int j = 0; j < n; j++) out[j] = in[j] * twist[j];
    fft(out, 0);
}

static void negacyclic_ifft_real(double out[n], double complex in[n]) {
    fft(in, 1);
    for (int j = 0; j < n; j++) out[j] = creal(in[j] * conj(twist[j]));
}

/* Approximate E[c_r | z0,c], omitting rejection-induced dependence. */
static void approximate_posterior_cr(double out[n], const poly *z0, const poly *c,
                                     const int32_t coordinates[tau]) {
    memset(out, 0, n * sizeof(*out));
    int off = 0;
    for (int g = 0; g < N; g++) {
        int len = taup;
        if (g == N - 1) len -= N * taup - tau;
        double lp = 0.0, lm = 0.0;
        for (int j = 0; j < len; j++) {
            int u = coordinates[off + j];
            int zp = z0->coeffs[u] - c->coeffs[u];
            int zm = z0->coeffs[u] + c->coeffs[u];
            lp += log_pmf[zp + bound0];
            lm += log_pmf[zm + bound0];
        }
        double m = tanh(0.5 * (lp - lm));
        for (int j = 0; j < len; j++) {
            int u = coordinates[off + j];
            out[u] = m * (double)c->coeffs[u];
        }
        off += len;
    }
}

#ifdef REFERENCE_REFINEMENT
/* Verifier-conditioned approximate posterior score.  Its likelihood model
   deliberately omits the dependence induced by rejection sampling. */
static void approximate_posterior_cr_z2(double out[n], const poly *z0,
                                        const poly z2p[k], const poly *c,
                                        const int32_t coordinates[tau],
                                        const poly coarse_d[k]) {
    poly block, products[N][k];
    double lp[N], lm[N], logw[1 << N];
    int off = 0;
    for (int g = 0; g < N; g++) {
        int len = taup - ((g == N - 1) ? (N * taup - tau) : 0);
        lp[g] = lm[g] = 0.0;
        for (int j = 0; j < len; j++) {
            int u = coordinates[off + j];
            lp[g] += log_pmf[z0->coeffs[u] - c->coeffs[u] + bound0];
            lm[g] += log_pmf[z0->coeffs[u] + c->coeffs[u] + bound0];
        }
        TruncPoly(&block, c, coordinates + off, len);
        for (int a = 0; a < k; a++)
            MultiplyPoly(&products[g][a], &block, coordinates + off, len, &coarse_d[a]);
        off += len;
    }
    const double noise_var = 350000.0;
    double zz = 0.0, zp[N] = {0}, pp[N][N] = {{0}};
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        double zv = z2p[a].coeffs[u];
        zz += zv * zv;
        for (int g = 0; g < N; g++) {
            double pg = products[g][a].coeffs[u];
            zp[g] += zv * pg;
            for (int h = 0; h <= g; h++)
                pp[g][h] += pg * products[h][a].coeffs[u];
        }
    }
    double maxlog = -HUGE_VAL;
    for (int mask = 0; mask < (1 << N); mask++) {
        double ss = zz, lw = 0.0;
        int signs[N];
        for (int g = 0; g < N; g++) {
            signs[g] = (mask >> g & 1) ? 1 : -1;
            lw += signs[g] > 0 ? lp[g] : lm[g];
            ss += 2.0 * signs[g] * zp[g] + pp[g][g];
            for (int h = 0; h < g; h++)
                ss += 2.0 * signs[g] * signs[h] * pp[g][h];
        }
        logw[mask] = lw - ss / (2.0 * noise_var);
        if (logw[mask] > maxlog) maxlog = logw[mask];
    }
    double denom = 0.0, means[N] = {0};
    for (int mask = 0; mask < (1 << N); mask++) {
        double w = exp(logw[mask] - maxlog);
        denom += w;
        for (int g = 0; g < N; g++) means[g] += ((mask >> g & 1) ? w : -w);
    }
    memset(out, 0, n * sizeof(*out));
    off = 0;
    for (int g = 0; g < N; g++) {
        int len = taup - ((g == N - 1) ? (N * taup - tau) : 0);
        double mean = means[g] / denom;
        for (int j = 0; j < len; j++) {
            int u = coordinates[off + j];
            out[u] = mean * c->coeffs[u];
        }
        off += len;
    }
}
#endif

static void reconstruct_z2(poly out[k], const poly zin[k + l + 1],
                           const poly *c, const poly A[k][l],
                           const poly t1_ntt[k]) {
    poly z[k + l + 1], cp = *c, w0[k], w1[k];
    memcpy(z, zin, sizeof(z));
    SubPoly(&cp, &z[0], &cp);
    for (int i = 0; i <= l; i++) z[i] = NTT(&z[i]);
    MatrixVectorNTT(w1, A, z + 1);
    ScalarVectorNTT(w0, z[0], t1_ntt);
    SubVector(w0, w1, w0);
    for (int i = 0; i < k; i++) INTT(&w0[i]);
    LazyReductionVector(w0);
    ExchangeModulus(w0, cp);
    HighBitsVector(w1, w0);
    hModpVector(w1, w1, z + l + 1, 0);
    CheckParityPoly(&cp, cp);
    ScalarVector(w1, alpha);
    SubVector(w1, w1, w0);
    AddPoly(&w1[0], &w1[0], &cp);
    HalfCenterModVector(w1);
    memcpy(out, w1, sizeof(w1));
}

static double complex sum_r[n], sum_z2[k][n], sum_z1[l][n];
static double sum_rr[n];
static double complex sum_rz2[k][n];
static double complex sum_z2z1[k][l][n];
#ifdef REFERENCE_REFINEMENT
static double complex esum_r[n], esum_z1[l][n], esum_rz1[l][n];
static double esum_rr[n];
static poly coarse_d_guess[k];

static int load_coarse_d_guess(const char *path) {
    FILE *f = fopen(path, "rb"); uint64_t magic = 0;
    if (!f) return -1;
    int ok = fread(&magic, sizeof(magic), 1, f) == 1
        && fread(coarse_d_guess, sizeof(coarse_d_guess), 1, f) == 1;
    fclose(f);
    return ok && magic == UINT64_C(0x4353313238423047) ? 0 : -1;
}
#endif
static uint8_t target_pk[PUBLICKEYBYTES], target_rho[SEEDBYTES];
static poly target_A[k][l], target_t1[k];
static const char *coarse_output_base;

static int save_coarse_d_guess(const char *suffix, double values[k][n], double scale) {
    if (!coarse_output_base) return 0;
    char path[1024];
    if (snprintf(path, sizeof(path), "%s.%s", coarse_output_base, suffix) >= (int)sizeof(path))
        return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    const uint64_t magic = UINT64_C(0x4353313238423047);
    poly rounded[k];
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        long long v = llround(scale * values[a][u]);
        if (v < -16) v = -16;
        if (v > 17) v = 17;
        rounded[a].coeffs[u] = (int32_t)v;
    }
    int ok = fwrite(&magic, sizeof(magic), 1, f) == 1
        && fwrite(rounded, sizeof(rounded), 1, f) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static int build_equivalent_components(const poly guessed_s1[l], poly s2_out[k],
                                       poly b0star_out[k]) {
    poly sn[l], product[k], submitted_rep[k], rounded_hi[k];
    for (int j = 0; j < l; j++) { sn[j] = guessed_s1[j]; sn[j] = NTT(&sn[j]); }
    MatrixVectorNTT(product, target_A, sn);
    for (int a = 0; a < k; a++) INTT(&product[a]);
    LazyReductionVector(product);
    const int choices[3] = {0, -1, 1};
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        int found = 0;
        for (int ci = 0; ci < 3 && !found; ci++) {
            int s2v = choices[ci], value = product[a].coeffs[u] + s2v;
            if (value < 0) value += q;
            if (value >= q) value -= q;
            int hi = (value + (1 << (beta - 1)) - 1) >> beta;
            if (hi == target_t1[a].coeffs[u]) {
                s2_out[a].coeffs[u] = s2v; found = 1;
            }
        }
        if (!found) s2_out[a].coeffs[u] = 0;
        int value = product[a].coeffs[u] + s2_out[a].coeffs[u];
        if (value < 0) value += q;
        if (value >= q) value -= q;
        submitted_rep[a].coeffs[u] = value;
    }
    /* Form b0* with the submitted implementation's exact centered/LowBits
       representative convention before secret-key encoding.  In this code,
       that convention is implemented by Power2RoundVector on [0,q) inputs. */
    Power2RoundVector(rounded_hi, b0star_out, submitted_rep);
    int invalid = 0;
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++)
        if (rounded_hi[a].coeffs[u] != target_t1[a].coeffs[u]) invalid++;
    return invalid;
}

static int forge_with_guess(const poly guessed_s1[l]) {
    poly equivalent_s2[k], b0star[k];
    int invalid = build_equivalent_components(guessed_s1, equivalent_s2, b0star);
    printf("public_key_consistency_invalid=%d/768\n", invalid);
    if (invalid) return 0;
    uint8_t K[SEEDBYTES], tr[HBYTES], esk[SECRETKEYBYTES], sig[SIGNATUREBYTES];
    uint8_t forge_seed[48], msg[] = "CS-128 recovered-key fresh-message forgery";
    for (int i = 0; i < SEEDBYTES; i++) K[i] = (uint8_t)(0xc3 + 13*i);
    H(tr, HBYTES, target_pk, PUBLICKEYBYTES);
    skEncode(esk, target_rho, K, tr, guessed_s1, equivalent_s2, b0star, target_t1);
    for (int i = 0; i < 48; i++) forge_seed[i] = (uint8_t)(0x19 + 5*i);
    init_random_number(&drng_algorithm, forge_seed, sizeof(forge_seed));
    int signed_ok = CS_Sign(sig, esk, msg, (int)sizeof(msg)-1) == 0;
    int verified = signed_ok && CS_Verify(target_pk, msg, (int)sizeof(msg)-1, sig);
    printf("equivalent_key_fresh_forgery=%s\n", verified ? "ACCEPT" : "REJECT");
    return verified;
}

typedef struct { int index; double margin; } uncertain_coeff;
static int cmp_uncertain(const void *aa, const void *bb) {
    const uncertain_coeff *a = (const uncertain_coeff *)aa;
    const uncertain_coeff *b = (const uncertain_coeff *)bb;
    return (a->margin > b->margin) - (a->margin < b->margin);
}

static int search_public_corrections(const poly initial[l], double values[l][n]) {
    uncertain_coeff order[l*n];
    for (int idx = 0; idx < l*n; idx++) {
        int j = idx/n, u = idx%n, base = initial[j].coeffs[u];
        double best_alt = HUGE_VAL;
        for (int v = -1; v <= 1; v++) if (v != base) {
            double d = values[j][u] - v;
            if (d*d < best_alt) best_alt = d*d;
        }
        double base_dist = values[j][u] - base;
        order[idx].index = idx; order[idx].margin = best_alt - base_dist*base_dist;
    }
    qsort(order, l*n, sizeof(order[0]), cmp_uncertain);
    poly trial[l], scratch_s2[k], scratch_b0star[k];
    const int top2 = 64;
    for (int ai = 0; ai < top2; ai++) {
        int p = order[ai].index, pj=p/n, pu=p%n, pv=initial[pj].coeffs[pu];
        for (int av=-1; av<=1; av++) if (av != pv) {
            memcpy(trial, initial, sizeof(trial)); trial[pj].coeffs[pu]=av;
            if (!build_equivalent_components(trial, scratch_s2, scratch_b0star)) {
                printf("public_correction_depth=1 index=%d\n", p);
                return forge_with_guess(trial);
            }
        }
    }
    for (int ai = 0; ai < top2; ai++) for (int bi = ai+1; bi < top2; bi++) {
        int p=order[ai].index, pj=p/n, pu=p%n, pv=initial[pj].coeffs[pu];
        int r=order[bi].index, rj=r/n, ru=r%n, rv=initial[rj].coeffs[ru];
        for (int av=-1; av<=1; av++) if (av != pv)
        for (int bv=-1; bv<=1; bv++) if (bv != rv) {
            memcpy(trial, initial, sizeof(trial));
            trial[pj].coeffs[pu]=av; trial[rj].coeffs[ru]=bv;
            if (!build_equivalent_components(trial, scratch_s2, scratch_b0star)) {
                printf("public_correction_depth=2 indices=%d,%d\n", p, r);
                return forge_with_guess(trial);
            }
        }
    }
    const int top3 = 24;
    for (int ai=0; ai<top3; ai++) for (int bi=ai+1; bi<top3; bi++)
    for (int ci=bi+1; ci<top3; ci++) {
        int p[3]={order[ai].index,order[bi].index,order[ci].index};
        int base[3]={initial[p[0]/n].coeffs[p[0]%n],initial[p[1]/n].coeffs[p[1]%n],initial[p[2]/n].coeffs[p[2]%n]};
        for(int a=-1;a<=1;a++) if(a!=base[0])
        for(int b=-1;b<=1;b++) if(b!=base[1])
        for(int c=-1;c<=1;c++) if(c!=base[2]) {
            memcpy(trial,initial,sizeof(trial));
            trial[p[0]/n].coeffs[p[0]%n]=a; trial[p[1]/n].coeffs[p[1]%n]=b; trial[p[2]/n].coeffs[p[2]%n]=c;
            if(!build_equivalent_components(trial,scratch_s2,scratch_b0star)) {
                printf("public_correction_depth=3 indices=%d,%d,%d\n",p[0],p[1],p[2]);
                return forge_with_guess(trial);
            }
        }
    }
    printf("public_correction_search=NO_SOLUTION\n");
    return 0;
}

static int save_state(const char *path, uint64_t count) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    const uint64_t magic =
#ifdef REFERENCE_REFINEMENT
        UINT64_C(0x4353313238524546);
#else
        UINT64_C(0x43533132384c454b);
#endif
    int ok = fwrite(&magic, sizeof(magic), 1, f) == 1
        && fwrite(&count, sizeof(count), 1, f) == 1
        && fwrite(sum_r, sizeof(sum_r), 1, f) == 1
        && fwrite(sum_z2, sizeof(sum_z2), 1, f) == 1
        && fwrite(sum_z1, sizeof(sum_z1), 1, f) == 1
        && fwrite(sum_rr, sizeof(sum_rr), 1, f) == 1
        && fwrite(sum_rz2, sizeof(sum_rz2), 1, f) == 1
        && fwrite(sum_z2z1, sizeof(sum_z2z1), 1, f) == 1;
#ifdef REFERENCE_REFINEMENT
    ok = ok && fwrite(esum_r, sizeof(esum_r), 1, f) == 1
        && fwrite(esum_z1, sizeof(esum_z1), 1, f) == 1
        && fwrite(esum_rz1, sizeof(esum_rz1), 1, f) == 1
        && fwrite(esum_rr, sizeof(esum_rr), 1, f) == 1;
#endif
    fclose(f);
    return ok ? 0 : -1;
}

static int add_state(const char *path, uint64_t *total) {
    FILE *f = fopen(path, "rb");
    uint64_t magic = 0, count = 0;
    double complex tr[n], tz2[k][n], tz1[l][n], trz2[k][n], tz2z1[k][l][n];
    double trr[n];
#ifdef REFERENCE_REFINEMENT
    double complex ter[n], tez1[l][n], terz1[l][n]; double terr[n];
#endif
    if (!f) return -1;
    int ok = fread(&magic, sizeof(magic), 1, f) == 1
        && fread(&count, sizeof(count), 1, f) == 1
        && fread(tr, sizeof(tr), 1, f) == 1
        && fread(tz2, sizeof(tz2), 1, f) == 1
        && fread(tz1, sizeof(tz1), 1, f) == 1
        && fread(trr, sizeof(trr), 1, f) == 1
        && fread(trz2, sizeof(trz2), 1, f) == 1
        && fread(tz2z1, sizeof(tz2z1), 1, f) == 1;
#ifdef REFERENCE_REFINEMENT
    ok = ok && fread(ter, sizeof(ter), 1, f) == 1
        && fread(tez1, sizeof(tez1), 1, f) == 1
        && fread(terz1, sizeof(terz1), 1, f) == 1
        && fread(terr, sizeof(terr), 1, f) == 1;
#endif
    fclose(f);
    if (!ok || magic !=
#ifdef REFERENCE_REFINEMENT
        UINT64_C(0x4353313238524546)
#else
        UINT64_C(0x43533132384c454b)
#endif
        ) return -1;
    *total += count;
    for (int u = 0; u < n; u++) {
        sum_r[u] += tr[u]; sum_rr[u] += trr[u];
        for (int a = 0; a < k; a++) {
            sum_z2[a][u] += tz2[a][u]; sum_rz2[a][u] += trz2[a][u];
            for (int j = 0; j < l; j++) sum_z2z1[a][j][u] += tz2z1[a][j][u];
        }
        for (int j = 0; j < l; j++) sum_z1[j][u] += tz1[j][u];
#ifdef REFERENCE_REFINEMENT
        esum_r[u] += ter[u]; esum_rr[u] += terr[u];
        for (int j = 0; j < l; j++) {
            esum_z1[j][u] += tez1[j][u]; esum_rz1[j][u] += terz1[j][u];
        }
#endif
    }
    return 0;
}

static void report(uint64_t count, const poly secret_s1[l],
                   const poly secret_s2[k], const poly true_b0[k]) {
#ifdef POISON_DIAGNOSTIC_TRUTH
    /* Negative control: replace every ground-truth array used by the reporting
       diagnostics.  Recovery, public completion, and forging must still take
       the same path because they depend only on the accumulated public state
       and the target public key. */
    poly poison_s1[l], poison_s2[k], poison_b0[k];
    for (int j = 0; j < l; j++) for (int u = 0; u < n; u++)
        poison_s1[j].coeffs[u] = (int32_t)(7 + ((j + u) & 1));
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        poison_s2[a].coeffs[u] = (int32_t)(-11 - ((a + u) & 1));
        poison_b0[a].coeffs[u] = (int32_t)(13 + ((a + u) & 1));
    }
    secret_s1 = poison_s1;
    secret_s2 = poison_s2;
    true_b0 = poison_b0;
#endif
    double complex bhat[k][n], shat[l][n];
    double breal[k][n], sreal[l][n];
    int berr = 0, serr = 0;
    double bmax = 0.0, smax = 0.0;

    for (int f = 0; f < n; f++) {
        double rr = sum_rr[f] - pow(cabs(sum_r[f]), 2.0) / (double)count;
        for (int a = 0; a < k; a++) {
            double complex rz = sum_rz2[a][f]
                - conj(sum_r[f]) * sum_z2[a][f] / (double)count;
            bhat[a][f] = -rz / rr;
        }
        double bnorm = 0.0;
        for (int a = 0; a < k; a++) bnorm += pow(cabs(bhat[a][f]), 2.0);
        for (int j = 0; j < l; j++) {
            double complex top = 0.0;
            for (int a = 0; a < k; a++) {
                double complex cross = sum_z2z1[a][j][f]
                    - sum_z2[a][f] * conj(sum_z1[j][f]) / (double)count;
                top += conj(bhat[a][f]) * cross;
            }
            /* top / bnorm estimates -tau*conj(s1). */
            shat[j][f] = conj(-top / ((double)count * (double)tau * bnorm));
        }
    }
    double bdot = 0.0, bnorm_time = 0.0;
    for (int a = 0; a < k; a++) {
        double complex tmp[n]; memcpy(tmp, bhat[a], sizeof(tmp));
        negacyclic_ifft_real(breal[a], tmp);
        for (int u = 0; u < n; u++) {
            bdot += breal[a][u] * true_b0[a].coeffs[u];
            bnorm_time += breal[a][u] * breal[a][u];
            double e = fabs(breal[a][u] - true_b0[a].coeffs[u]);
            if (e > bmax) bmax = e;
            if (llround(breal[a][u]) != true_b0[a].coeffs[u]) berr++;
        }
    }
    for (int j = 0; j < l; j++) {
        double complex tmp[n]; memcpy(tmp, shat[j], sizeof(tmp));
        negacyclic_ifft_real(sreal[j], tmp);
        for (int u = 0; u < n; u++) {
            double e = fabs(sreal[j][u] - secret_s1[j].coeffs[u]);
            if (e > smax) smax = e;
            if (llround(sreal[j][u]) != secret_s1[j].coeffs[u]) serr++;
        }
    }
    poly guessed_s1[l];
    for (int j = 0; j < l; j++) for (int u = 0; u < n; u++)
        guessed_s1[j].coeffs[u] = (int32_t)llround(sreal[j][u]);
    double bscale = bdot / bnorm_time;
    int berr_scaled = 0;
    double bmax_scaled = 0.0;
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        double e = fabs(bscale * breal[a][u] - true_b0[a].coeffs[u]);
        if (e > bmax_scaled) bmax_scaled = e;
        if (llround(bscale * breal[a][u]) != true_b0[a].coeffs[u]) berr_scaled++;
    }
    double qscale0 = sqrt(85.5 * (double)(k*n) / bnorm_time);
    double qscale = qscale0, qbest = HUGE_VAL;
    for (int si = -600; si <= 600; si++) {
        double scale = qscale0 + 0.00005 * si, objective = 0.0;
        if (scale <= 0.0) continue;
        for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
            double value = scale * breal[a][u];
            double nearest = round(value);
            if (nearest < -15.0) nearest = -15.0;
            if (nearest > 16.0) nearest = 16.0;
            double d = value - nearest;
            objective += d*d;
        }
        if (objective < qbest) { qbest = objective; qscale = scale; }
    }
    int berr_quant = 0, serr_quant = 0;
    double bmax_quant = 0.0, smax_quant = 0.0;
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        double e = fabs(qscale * breal[a][u] - true_b0[a].coeffs[u]);
        if (e > bmax_quant) bmax_quant = e;
        if (llround(qscale * breal[a][u]) != true_b0[a].coeffs[u]) berr_quant++;
    }
    for (int j = 0; j < l; j++) for (int u = 0; u < n; u++) {
        sreal[j][u] /= qscale;
        double e = fabs(sreal[j][u] - secret_s1[j].coeffs[u]);
        if (e > smax_quant) smax_quant = e;
        if (llround(sreal[j][u]) != secret_s1[j].coeffs[u]) serr_quant++;
        guessed_s1[j].coeffs[u] = (int32_t)llround(sreal[j][u]);
        if (guessed_s1[j].coeffs[u] < -1) guessed_s1[j].coeffs[u] = -1;
        if (guessed_s1[j].coeffs[u] > 1) guessed_s1[j].coeffs[u] = 1;
    }
    save_coarse_d_guess("raw", breal, 1.0);
    save_coarse_d_guess("quant", breal, qscale);
    printf("checkpoint=%llu b0_errors=%d/768 b0_maxerr=%.6f bscale=%.8f "
           "b0_scaled_errors=%d b0_scaled_maxerr=%.6f s1_errors=%d/768 s1_maxerr=%.6f "
           "qscale=%.8f b0_quant_errors=%d b0_quant_maxerr=%.6f "
           "s1_quant_errors=%d s1_quant_maxerr=%.6f\n",
           (unsigned long long)count, berr, bmax, bscale, berr_scaled,
           bmax_scaled, serr, smax, qscale, berr_quant, bmax_quant,
           serr_quant, smax_quant);
    /* The baseline regression estimates d=b0-s2.  Comparisons with b0 above
       are retained for compatibility with older logs; these are diagnostics
       only and do not feed the attack. */
    int derr = 0; double dmax = 0.0, dmae = 0.0, drmse = 0.0;
    for (int a = 0; a < k; a++) for (int u = 0; u < n; u++) {
        int32_t d = true_b0[a].coeffs[u] - secret_s2[a].coeffs[u];
        double e = fabs(breal[a][u] - d);
        if (e > dmax) dmax = e;
        dmae += e;
        drmse += e * e;
        if (llround(breal[a][u]) != d) derr++;
    }
    printf("coarse_d_errors=%d/768 coarse_d_mae=%.6f coarse_d_rmse=%.6f "
           "coarse_d_maxerr=%.6f\n", derr, dmae/(k*n), sqrt(drmse/(k*n)), dmax);
#ifdef REFERENCE_REFINEMENT
    int posterior_err = 0; double posterior_max = 0.0;
    poly posterior_guess[l], best_public_guess[l], scratch_s2[k], scratch_b0star[k];
    double posterior_values[l][n];
    for (int j = 0; j < l; j++) {
        double complex estimate[n];
        for (int f = 0; f < n; f++) {
            double rr = esum_rr[f] - pow(cabs(esum_r[f]), 2.0)/(double)count;
            double complex rz = esum_rz1[j][f]
                - conj(esum_r[f])*esum_z1[j][f]/(double)count;
            estimate[f] = rz/rr;
        }
        double values[n]; negacyclic_ifft_real(values, estimate);
        for (int u = 0; u < n; u++) {
            posterior_values[j][u] = values[u];
            double abs_err = fabs(values[u] - secret_s1[j].coeffs[u]);
            if (abs_err > posterior_max) posterior_max = abs_err;
            if (llround(values[u]) != secret_s1[j].coeffs[u]) posterior_err++;
            long long v = llround(values[u]); if (v < -1) v = -1; if (v > 1) v = 1;
            posterior_guess[j].coeffs[u] = (int32_t)v;
        }
    }
    printf("approx_posterior_s1_errors=%d/768 approx_posterior_s1_maxerr=%.6f\n",
           posterior_err, posterior_max);
    if (!build_equivalent_components(posterior_guess, scratch_s2, scratch_b0star)) {
        printf("public_correction_depth=0\n");
        forge_with_guess(posterior_guess);
        fflush(stdout);
        return;
    }
    int best_invalid = k*n + 1; double best_scale = 1.0;
    for (int si = 0; si <= 3000; si++) {
        double scale = 0.7 + 0.0002*si;
        poly trial[l];
        for (int j = 0; j < l; j++) for (int u = 0; u < n; u++) {
            long long v = llround(scale*posterior_values[j][u]);
            if (v < -1) v = -1; if (v > 1) v = 1;
            trial[j].coeffs[u] = (int32_t)v;
        }
        int invalid = build_equivalent_components(trial, scratch_s2, scratch_b0star);
        if (invalid < best_invalid) {
            best_invalid = invalid; best_scale = scale; memcpy(best_public_guess, trial, sizeof(trial));
            if (!invalid) break;
        }
    }
    printf("approx_posterior_public_scale=%.8f approx_posterior_best_invalid=%d/768\n",
           best_scale, best_invalid);
    printf("approx_posterior_"); forge_with_guess(best_public_guess);
    search_public_corrections(posterior_guess, posterior_values);
#endif
    fflush(stdout);
}

int main(int argc, char **argv) {
    int recover_mode = argc > 1 && strcmp(argv[1], "--recover-d") == 0;
    int merge_mode = recover_mode || (argc > 1 && strcmp(argv[1], "--merge") == 0);
    uint64_t total = (!merge_mode && argc > 1) ? strtoull(argv[1], NULL, 0) : 10000;
    uint64_t every = (!merge_mode && argc > 2) ? strtoull(argv[2], NULL, 0) : total;
    unsigned worker = (!merge_mode && argc > 3) ? (unsigned)strtoul(argv[3], NULL, 0) : 0;
    const char *state_path = (!merge_mode && argc > 4) ? argv[4] : NULL;
#ifdef REFERENCE_REFINEMENT
    const char *coarse_guess_path = (!merge_mode && argc > 5) ? argv[5] : NULL;
#endif
    uint8_t seed[48], pk[PUBLICKEYBYTES], sk[SECRETKEYBYTES];
    uint8_t sig[SIGNATUREBYTES], cwave[HBYTES], rho[SEEDBYTES], K[SEEDBYTES], tr[HBYTES];
    poly A[k][l], t1[k], t1_ntt[k], secret[k + l], true_b0[k], dummy_t1[k];
    clock_t started = clock();

    init_pmf();
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x51 + 7 * i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    CS_KeyGen(pk, sk);
    skDecode(rho, K, tr, secret, true_b0, dummy_t1, sk);
    pkDecode(rho, t1, pk);
    ExpandA(A, rho);
    memcpy(target_pk, pk, sizeof(target_pk));
    memcpy(target_rho, rho, sizeof(target_rho));
    memcpy(target_A, A, sizeof(target_A));
    memcpy(target_t1, t1, sizeof(target_t1));
#ifdef REFERENCE_REFINEMENT
    if (!merge_mode && (!coarse_guess_path || load_coarse_d_guess(coarse_guess_path))) {
        fprintf(stderr, "cannot read coarse d guess %s\n",
                coarse_guess_path ? coarse_guess_path : "(missing)");
        return 7;
    }
#endif
    memcpy(t1_ntt, t1, sizeof(t1));
    ShiftLeftVector(t1_ntt, beta);
    for (int a = 0; a < k; a++) t1_ntt[a] = NTT(&t1_ntt[a]);

    if (merge_mode) {
        uint64_t merged = 0;
        int first_state = recover_mode ? 3 : 2;
        if (recover_mode) {
            if (argc < 4) { fprintf(stderr, "--recover-d OUTBASE STATE...\n"); return 4; }
            coarse_output_base = argv[2];
        }
        for (int i = first_state; i < argc; i++) {
            if (add_state(argv[i], &merged)) {
                fprintf(stderr, "cannot read state %s\n", argv[i]);
                return 4;
            }
        }
        report(merged, secret, secret + l, true_b0);
        return 0;
    }

    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(0xa7 + 11 * i + 37 * worker);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;

    for (uint64_t it = 1; it <= total; it++) {
        uint8_t msg[16];
        memcpy(msg, &it, sizeof(it));
        uint64_t tag = it ^ 0x43532d313238ULL ^ ((uint64_t)worker << 48);
        memcpy(msg + 8, &tag, sizeof(tag));
        if (CS_Sign(sig, sk, msg, sizeof(msg)) != 0) { it--; continue; }
        if (it == 1 && !CS_Verify(pk, msg, sizeof(msg), sig)) {
            fprintf(stderr, "reference signature rejected\n");
            return 6;
        }

        poly z[k + l + 1], c, z2p[k];
        int32_t coords[tau];
        double rpost[n];
        if (sigDecode(cwave, z, sig)) return 3;
        SampleInBall(&c, coords, cwave);
        approximate_posterior_cr(rpost, &z[0], &c, coords);
        reconstruct_z2(z2p, z, &c, A, t1_ntt);
#ifdef REFERENCE_REFINEMENT
        double erpost[n];
        approximate_posterior_cr_z2(erpost, &z[0], z2p, &c, coords,
                                    coarse_d_guess);
#endif

        double complex rf[n], z2f[k][n], z1f[l][n];
        negacyclic_fft_double(rf, rpost);
        for (int a = 0; a < k; a++) negacyclic_fft_i32(z2f[a], z2p[a].coeffs);
        for (int j = 0; j < l; j++) negacyclic_fft_i32(z1f[j], z[1 + j].coeffs);
        for (int f = 0; f < n; f++) {
            sum_r[f] += rf[f];
            sum_rr[f] += pow(cabs(rf[f]), 2.0);
            for (int a = 0; a < k; a++) {
                sum_z2[a][f] += z2f[a][f];
                sum_rz2[a][f] += conj(rf[f]) * z2f[a][f];
                for (int j = 0; j < l; j++)
                    sum_z2z1[a][j][f] += z2f[a][f] * conj(z1f[j][f]);
            }
            for (int j = 0; j < l; j++) sum_z1[j][f] += z1f[j][f];
        }
#ifdef REFERENCE_REFINEMENT
        double complex erf[n]; negacyclic_fft_double(erf, erpost);
        for (int f = 0; f < n; f++) {
            esum_r[f] += erf[f]; esum_rr[f] += pow(cabs(erf[f]),2.0);
            for (int j = 0; j < l; j++) {
                esum_z1[j][f] += z1f[j][f];
                esum_rz1[j][f] += conj(erf[f])*z1f[j][f];
            }
        }
#endif
        if (it % every == 0 || it == total) {
            double sec = (double)(clock() - started) / CLOCKS_PER_SEC;
            printf("checkpoint=%llu elapsed_cpu=%.3f rate=%.1f_sig_s\n",
                   (unsigned long long)it, sec, (double)it / sec);
            fflush(stdout);
            if (state_path && it < total) {
                char checkpoint_path[1200];
                int written = snprintf(checkpoint_path, sizeof(checkpoint_path),
                                       "%s.%llu", state_path,
                                       (unsigned long long)it);
                if (written < 0 || written >= (int)sizeof(checkpoint_path)
                    || save_state(checkpoint_path, it)) return 5;
                if (getenv("CS_PAUSE_AT_CHECKPOINT")) {
                    printf("checkpoint_state_ready=%llu\n",
                           (unsigned long long)it);
                    fflush(stdout);
                    if (getchar() == EOF) return 8;
                }
            }
        }
    }
    if (state_path && save_state(state_path, total)) return 5;
    return 0;
}

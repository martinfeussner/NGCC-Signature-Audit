/* Specification-conformant Galas oracle used only by the design audit. */
#ifndef GALAS_SIG_SPEC_ORACLE_H
#define GALAS_SIG_SPEC_ORACLE_H

#ifndef GALAS_INSTANCE
#define GALAS_INSTANCE GALAS_160F
#endif
#ifndef GALAS_INSTANCE_NAME
#define GALAS_INSTANCE_NAME "Galas-160F"
#endif

#ifdef __cplusplus
extern "C" {
#endif

unsigned long long spec_sig_get_pk_len_bytes(void);
unsigned long long spec_sig_get_sk_len_bytes(void);
unsigned long long spec_sig_get_sn_len_bytes(void);

/* Deterministic seeded sampler for Algorithm 19.  A caller supplies an
   independently uniform seed; there is no public default seed. */
int spec_sig_keygen_seeded(unsigned char* pk, unsigned long long* pk_len_bytes,
                           unsigned char* sk, unsigned long long* sk_len_bytes,
                           const unsigned char* seed,
                           unsigned long long seed_len_bytes);

/* Algorithms 21 and 22.  The normative signer receives pk and sk=k. */
int spec_sig_sign(const unsigned char* pk, unsigned long long pk_len_bytes,
                  const unsigned char* sk, unsigned long long sk_len_bytes,
                  const unsigned char* m, unsigned long long m_len_bytes,
                  unsigned char* sn, unsigned long long* sn_len_bytes);

int spec_sig_verify(const unsigned char* pk, unsigned long long pk_len_bytes,
                    const unsigned char* sn, unsigned long long sn_len_bytes,
                    const unsigned char* m, unsigned long long m_len_bytes);

#ifdef __cplusplus
}
#endif
#endif

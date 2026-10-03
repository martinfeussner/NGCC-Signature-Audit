#ifndef CEDRUS_C_VERIFY_CORE_H
#define CEDRUS_C_VERIFY_CORE_H

#include <stddef.h>
#include <stdint.h>

/* The coherent written verifier interpretation used by the attack. */
int cedrus_c_verify_coherent(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pk);

/* The same verifier with the WOTS+C zero-prefix/fixed-sum membership test
 * restored before every call to Algorithm 6. */
int cedrus_c_verify_strict(const uint8_t *sig, size_t siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *pk);

#endif

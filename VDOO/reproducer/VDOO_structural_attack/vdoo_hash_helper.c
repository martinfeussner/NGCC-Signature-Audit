#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "auxfunc.h"

/* Compute the exact VDOO-128 verification target:
 * pseudoXOF_280(pseudoXOF_256(message) || salt).
 */
int vdoo_hash_target(unsigned char out[35],
                     const unsigned char *message, size_t message_len,
                     const unsigned char salt[16])
{
    unsigned char digest[32];
    unsigned char digest_salt[48];
    int rc = pseudoXOF(256, message, (unsigned long long)message_len * 8, digest);
    if (rc != 0)
        return rc;
    memcpy(digest_salt, digest, 32);
    memcpy(digest_salt + 32, salt, 16);
    return pseudoXOF(280, digest_salt, 48 * 8, out);
}

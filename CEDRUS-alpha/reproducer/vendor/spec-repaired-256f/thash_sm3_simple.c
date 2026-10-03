#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "auxfunc.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[64 + 22 + inblocks*SPX_N];
    unsigned char temp_out[32];
    const unsigned char *a = (const unsigned char *)addr;

    memcpy(buf, pub_seed, SPX_N);
    memset(buf + SPX_N, 0, 64 - SPX_N);
    buf[64] = a[SPX_OFFSET_LAYER];
    memcpy(buf + 65, a + SPX_OFFSET_TREE, 8);
    buf[73] = a[SPX_OFFSET_TYPE];
    memcpy(buf + 74, a + 20, 12);
    memcpy(buf + 86, in, inblocks * SPX_N);

    sm3hash(256, buf, (unsigned long long)sizeof(buf) * 8, temp_out);
    memcpy(out, temp_out, SPX_N);
}

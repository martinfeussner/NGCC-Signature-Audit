/* NGCC forwarding header for sign-07 CS (see Makefile).
 *
 * ntt.c does #include "NTT.h", but the submission only ships ntt.h, and ntt.h
 * declares `void MultiplyNTT(...)` while ntt.c defines it `static` (a hard
 * error in C). So the NTT.h that ntt.c was compiled against is missing from
 * the submission. This stand-in includes ntt.h with that one prototype
 * renamed away, so ntt.c's static definition does not clash. MultiplyNTT is
 * only used inside ntt.c. No submission file is modified.
 */
#ifndef NGCC_NTT_FORWARD_H
#define NGCC_NTT_FORWARD_H
#define MultiplyNTT MultiplyNTT_unused_decl
#include "ntt_decl.h"
#undef MultiplyNTT
#endif

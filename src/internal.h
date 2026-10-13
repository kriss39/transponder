#ifndef TRANSPONDER_INTERNAL_H
#define TRANSPONDER_INTERNAL_H

/* Not part of the public API. */

#include "transponder/keccak.h"

/*
 * FIPS-202 SHA3-256 on the same sponge as Keccak-256; only the padding
 * byte differs. Used by the tests to check the permutation against an
 * independent implementation (Python's hashlib).
 */
void trp__sha3_256_final(trp_keccak_ctx *ctx, uint8_t out[TRP_KECCAK256_LEN]);

#endif

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

/* Write code point `cp` as UTF-8 into `out` (up to 4 bytes); returns the byte count, 0 if invalid. */
size_t trp__utf8_put(uint32_t cp, char out[4]);

/* Value of one hex digit, or -1. */
int trp__hex_nibble(char c);

#endif

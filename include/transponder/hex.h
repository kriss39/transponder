#ifndef TRANSPONDER_HEX_H
#define TRANSPONDER_HEX_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Write `len` bytes as lowercase hex into `out`, NUL-terminated, with a
 * leading "0x" when `prefix` is non-zero. `out_cap` counts the NUL.
 */
trp_err_t trp_hex_encode(const uint8_t *data, size_t len, int prefix,
                         char *out, size_t out_cap);

/*
 * Decode `len` hex characters (an optional "0x" prefix is skipped) into
 * `out`. Accepts upper and lower case. An odd number of digits is invalid.
 */
trp_err_t trp_hex_decode(const char *hex, size_t len, uint8_t *out,
                         size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif

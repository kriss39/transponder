#ifndef TRANSPONDER_BASE64URL_H
#define TRANSPONDER_BASE64URL_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Output size of encoding `len` bytes, without padding and without the NUL. */
#define TRP_BASE64URL_ENCODED_LEN(len) (((len) / 3) * 4 + ((len) % 3 ? (len) % 3 + 1 : 0))

/* Encode as base64url without padding (RFC 4648 section 5), NUL-terminated. */
trp_err_t trp_base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_cap);

/*
 * Decode base64url. Padding is not part of the MPP wire format, but up to
 * two trailing '=' are tolerated. Standard base64 characters ('+', '/')
 * and anything else outside the alphabet are rejected.
 */
trp_err_t trp_base64url_decode(const char *in, size_t len, uint8_t *out, size_t out_cap,
                               size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif

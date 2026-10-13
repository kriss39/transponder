#ifndef TRANSPONDER_RECEIPT_H
#define TRANSPONDER_RECEIPT_H

#include "transponder/common.h"
#include "transponder/json.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A `Payment-Receipt` header: base64url JSON with at least `status`,
 * `method`, `timestamp` (RFC 3339) and `reference` (for Tempo, the
 * transaction hash). The strings are unescaped into the scratch buffer.
 */
typedef struct {
    trp_str status;
    trp_str method;
    trp_str timestamp;
    trp_str reference;
    trp_json json; /* the whole decoded receipt, for any extra fields */
} trp_receipt;

/* `scratch` must hold at least 2 * len + 16 bytes. Surrounding whitespace is ignored. */
trp_err_t trp_receipt_parse(const char *value, size_t len, trp_receipt *out, char *scratch,
                            size_t scratch_cap);

#ifdef __cplusplus
}
#endif

#endif

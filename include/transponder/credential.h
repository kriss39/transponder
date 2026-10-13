#ifndef TRANSPONDER_CREDENTIAL_H
#define TRANSPONDER_CREDENTIAL_H

#include "transponder/challenge.h"
#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Build the credential header value `Payment <base64url(json)>` for a
 * challenge, NUL-terminated in `out`.
 *
 * The JSON is {"challenge": {...echoed parameters...}, "payload": ...,
 * "source": ...} with keys in the order mppx writes them. `payload_json`
 * is the method-specific payload object, already serialized (for Tempo,
 * e.g. {"type":"transaction","signature":"0x76..."}). `source` is the
 * payer DID, or NULL to omit it. `scratch` holds the JSON before encoding.
 *
 * Send the result in the header named by trp_challenge_credential_header().
 */
trp_err_t trp_credential_encode(const trp_challenge *challenge, const char *payload_json,
                                size_t payload_len, const char *source, char *out,
                                size_t out_cap, char *scratch, size_t scratch_cap);

#ifdef __cplusplus
}
#endif

#endif

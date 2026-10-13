#ifndef TRANSPONDER_CHALLENGE_H
#define TRANSPONDER_CHALLENGE_H

#include "transponder/common.h"
#include "transponder/json.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Largest `request` auth-param accepted, in encoded characters (same cap as mppx). */
#define TRP_CHALLENGE_MAX_REQUEST (16 * 1024)

/*
 * A parsed `WWW-Authenticate: Payment` challenge. Every string is unescaped,
 * NUL-terminated and stored in the scratch buffer given to the parser.
 * Optional parameters that were absent have a NULL `ptr`.
 */
typedef struct {
    trp_str id;
    trp_str realm;
    trp_str method;
    trp_str intent;
    trp_str request; /* base64url text, echoed unchanged in the credential */
    trp_str description;
    trp_str digest;
    trp_str expires;
    trp_str header; /* "Payment-Authorization" when the challenge selects that field */
    trp_str opaque;
    trp_json request_json; /* the decoded `request`, always a JSON object */
} trp_challenge;

/*
 * Parse the first Payment challenge in a WWW-Authenticate field value.
 * `scratch` must hold at least 2 * len + 16 bytes.
 *
 * Follows the reference SDK (mppx): the scheme name is case-insensitive,
 * unknown parameters are ignored, a repeated parameter or a missing id,
 * realm, method, intent or request is an error, and `request` must be
 * base64url-encoded JSON describing an object.
 */
trp_err_t trp_challenge_parse(const char *value, size_t len, trp_challenge *out,
                              char *scratch, size_t scratch_cap);

/*
 * Find the first Payment challenge in `value` whose method and intent match
 * (NULL matches anything). Challenges that fail to parse are skipped.
 * TRP_ERR_NOT_FOUND if none matches.
 */
trp_err_t trp_challenge_select(const char *value, size_t len, const char *method,
                               const char *intent, trp_challenge *out, char *scratch,
                               size_t scratch_cap);

/* The request header that must carry the credential for this challenge. */
const char *trp_challenge_credential_header(const trp_challenge *challenge);

#ifdef __cplusplus
}
#endif

#endif

#ifndef TRANSPONDER_CHARGE_H
#define TRANSPONDER_CHARGE_H

#include "transponder/challenge.h"
#include "transponder/common.h"
#include "transponder/tempo.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Something that holds a P-256 key and signs 32-byte digests with it: a
 * secure element on a device, or a software key on a computer. The digest
 * is signed as is (no extra hashing). `s` may be high or low; the encoder
 * normalizes it.
 */
typedef struct {
    trp_err_t (*sign_digest)(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32]);
    void *ctx;
    uint8_t public_key[TRP_P256_PUBKEY_LEN]; /* x || y */
} trp_signer;

/* What the caller supplies besides the challenge. */
typedef struct {
    const uint8_t *owner;     /* the account the access key pays for, TRP_ADDRESS_LEN bytes */
    const trp_signer *signer; /* the access key */
    uint64_t now;             /* unix seconds; must be right to within a few seconds */
    uint64_t valid_after;     /* a random past timestamp, or 0 for none (see DESIGN.md) */
    uint64_t default_chain_id;  /* used when the request names no chainId; 0 to require one */
    uint64_t gas_limit;
    uint64_t max_fee_per_gas;
    uint64_t max_priority_fee_per_gas;
    const uint8_t *fee_token; /* when the client pays fees; NULL lets the chain choose */
    trp_str client_id;        /* optional, goes into the attribution memo */
} trp_charge_options;

/* How long a signed charge stays valid at most, as in the reference SDK. */
#define TRP_CHARGE_MAX_VALIDITY 25

/*
 * Answer a Tempo `charge` challenge in pull mode: build the transfer, sign
 * it as a Keychain V2 access-key transaction, and write the credential
 * header value (`Payment ...`) to `out`. `work` is scratch space; 4 KB is
 * plenty for one transfer and a typical challenge.
 *
 * Returns TRP_ERR_UNSUPPORTED for what this version does not do yet:
 * zero-amount (proof) charges, split payments, and push-only challenges.
 */
trp_err_t trp_tempo_charge(const trp_challenge *challenge, const trp_charge_options *options,
                           char *out, size_t out_cap, uint8_t *work, size_t work_cap);

/* An RFC 3339 timestamp ("2026-01-29T12:05:00Z", offsets and fractions allowed) as unix seconds. */
trp_err_t trp_parse_rfc3339(const char *s, size_t len, uint64_t *out);

/* An address as EIP-55 mixed-case hex with "0x" (43 bytes with the NUL). */
void trp_address_checksum(const uint8_t address[TRP_ADDRESS_LEN], char out[43]);

#ifdef __cplusplus
}
#endif

#endif

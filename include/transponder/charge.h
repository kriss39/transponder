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
 * secure element on a device, the Secure Enclave of a Mac, or a software
 * key. `s` may be high or low; the encoder normalizes it. Zero the struct
 * before filling it in; the ports in ports/ do this for you.
 */
typedef struct {
    trp_err_t (*sign_digest)(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32]);
    void *ctx;
    uint8_t public_key[TRP_P256_PUBKEY_LEN]; /* x || y */
    int pre_hash; /* non-zero if sign_digest signs SHA-256(digest), as CryptoKit does */
} trp_signer;

/* Chain IDs. A charge request without methodDetails.chainId means Moderato, per the spec. */
#define TRP_TEMPO_MAINNET 4217
#define TRP_TEMPO_MODERATO 42431

#define TRP_MAX_SPLITS 4

/* One extra recipient of a split payment. */
typedef struct {
    uint8_t amount[TRP_U256_LEN];
    uint8_t recipient[TRP_ADDRESS_LEN];
    int has_memo;
    uint8_t memo[TRP_MEMO_LEN];
} trp_charge_split;

/* Everything a Tempo charge challenge asks the device to pay, parsed once. */
typedef struct {
    uint8_t amount[TRP_U256_LEN];      /* total, in base units; includes the splits */
    uint8_t currency[TRP_ADDRESS_LEN]; /* TIP-20 token */
    uint8_t recipient[TRP_ADDRESS_LEN];
    uint64_t chain_id;
    int fee_payer;                     /* the server sponsors the network fee */
    int has_memo;
    uint8_t memo[TRP_MEMO_LEN];        /* a server-required memo, if has_memo */
    size_t split_count;
    trp_charge_split splits[TRP_MAX_SPLITS];
    uint64_t expires;                  /* unix seconds, 0 if the challenge sets none */
} trp_charge_request;

/*
 * Read a Tempo charge challenge's request. TRP_ERR_UNSUPPORTED for what
 * this version does not do: zero-amount (proof) charges, push-only
 * challenges, and more than TRP_MAX_SPLITS splits.
 */
trp_err_t trp_charge_request_parse(const trp_challenge *challenge, trp_charge_request *out);

/*
 * What the device agrees to pay. The server writes the challenge, so the
 * device checks it against limits of its own before it signs anything.
 * List fields are allow-lists; a count of 0 allows any value.
 */
typedef struct {
    uint8_t max_amount[TRP_U256_LEN];                /* per payment, base units; must be non-zero */
    const uint8_t (*tokens)[TRP_ADDRESS_LEN];
    size_t token_count;
    const uint8_t (*recipients)[TRP_ADDRESS_LEN];    /* checked for the recipient and every split */
    size_t recipient_count;
    const uint64_t *chain_ids;
    size_t chain_id_count;
} trp_spend_policy;

/* TRP_OK if the policy allows the request, TRP_ERR_DENIED if not. */
trp_err_t trp_spend_policy_check(const trp_spend_policy *policy, const trp_charge_request *request);

/* What the caller supplies besides the challenge. */
typedef struct {
    const uint8_t *owner;            /* the account the access key pays for, TRP_ADDRESS_LEN bytes */
    const trp_signer *signer;        /* the access key */
    const trp_spend_policy *policy;  /* required */
    /* Optional last say before signing, e.g. a button on the device. Return TRP_OK to pay. */
    trp_err_t (*approve)(void *ctx, const trp_challenge *challenge, const trp_charge_request *request);
    void *approve_ctx;
    uint64_t now;                    /* unix seconds; must be right to within a few seconds */
    uint64_t valid_after;            /* a random past timestamp, or 0 for none (see DESIGN.md) */
    uint64_t gas_limit;
    uint64_t max_fee_per_gas;
    uint64_t max_priority_fee_per_gas;
    const uint8_t *fee_token;        /* when the client pays fees; NULL lets the chain choose */
    trp_str client_id;               /* optional, goes into the attribution memo */
} trp_charge_options;

/* What trp_tempo_charge signed. */
typedef struct {
    trp_charge_request request;
    /*
     * keccak256 of the signed transaction. When the server sponsors the fee
     * (request.fee_payer) it adds its own signature, which changes the hash,
     * so the receipt's reference only matches this when fee_payer is 0.
     * All zeros for a proof.
     */
    uint8_t tx_hash[32];
    int proof; /* 1 when the challenge was for zero and nothing was paid */
} trp_charge_result;

/* How long a signed charge stays valid at most, as in the reference SDK. */
#define TRP_CHARGE_MAX_VALIDITY 25

/*
 * Answer a Tempo `charge` challenge in pull mode: check it against the
 * policy (and `approve`), build the transfer, sign it as a Keychain V2
 * access-key transaction, and write the credential header value
 * (`Payment ...`) to `out`. `work` is scratch space: 4 KB covers one
 * transfer and a typical challenge; allow about 1.5 KB more per split
 * (8 KB covers TRP_MAX_SPLITS). `out`: 2 KB without splits, 4.5 KB with four.
 * `result` may be NULL.
 *
 * A challenge for an amount of zero asks the device to prove who it pays
 * for, not to pay: the answer is a `proof` credential, the access key's
 * signature over trp_proof_digest, and no transaction. The policy and
 * `approve` are still consulted, since a proof reveals the owner's address.
 */
trp_err_t trp_tempo_charge(const trp_challenge *challenge, const trp_charge_options *options,
                           char *out, size_t out_cap, uint8_t *work, size_t work_cap,
                           trp_charge_result *result);

/*
 * The EIP-712 digest a zero-amount proof signs: Proof(address account,
 * string challengeId, string realm) in the domain {name "MPP", version "3",
 * chainId}. An access key signs it as Keychain V2, through
 * trp_tempo_keychain_digest, like a transaction.
 */
void trp_proof_digest(uint64_t chain_id, const uint8_t account[TRP_ADDRESS_LEN], trp_str challenge_id,
                      trp_str realm, uint8_t out[32]);

/* An RFC 3339 timestamp ("2026-01-29T12:05:00Z", offsets and fractions allowed) as unix seconds. */
trp_err_t trp_parse_rfc3339(const char *s, size_t len, uint64_t *out);

/* An address as EIP-55 mixed-case hex with "0x" (43 bytes with the NUL). */
void trp_address_checksum(const uint8_t address[TRP_ADDRESS_LEN], char out[43]);

#ifdef __cplusplus
}
#endif

#endif

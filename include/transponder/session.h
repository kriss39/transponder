#ifndef TRANSPONDER_SESSION_H
#define TRANSPONDER_SESSION_H

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/common.h"
#include "transponder/tempo.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * MPP `session` payments on Tempo (sessionProtocol "v2", the TIP-20 channel
 * escrow precompile of TIP-1034): the device deposits once, then pays for
 * each request with an off-chain voucher, a signature over a growing
 * cumulative amount. Only v2 is supported.
 *
 * One P-256 key does everything: it signs the channel's open and top-up
 * transactions as a Keychain V2 access key for the owner, and it is the
 * channel's authorizedSigner, signing vouchers as a primitive P-256
 * signature (TIP-1020). So the vouchers, too, come from the secure element.
 */

/* The TIP-20 channel escrow precompile ("MPP" in ASCII, then zeros). */
extern const uint8_t TRP_CHANNEL_ESCROW[TRP_ADDRESS_LEN];

/* v2 amounts are uint96. */
#define TRP_SESSION_MAX_AMOUNT_BITS 96

/* The channel as TIP-1034 identifies it. */
typedef struct {
    uint8_t payer[TRP_ADDRESS_LEN];
    uint8_t payee[TRP_ADDRESS_LEN];
    uint8_t operator_[TRP_ADDRESS_LEN];
    uint8_t token[TRP_ADDRESS_LEN];
    uint8_t salt[32];
    uint8_t authorized_signer[TRP_ADDRESS_LEN];
    uint8_t expiring_nonce_hash[32];
} trp_channel_descriptor;

/* channelId = keccak256(abi.encode(payer, payee, operator, token, salt, authorizedSigner, expiringNonceHash, escrow, chainId)). */
void trp_channel_id(const trp_channel_descriptor *d, const uint8_t escrow[TRP_ADDRESS_LEN],
                    uint64_t chain_id, uint8_t out[32]);

/* The EIP-712 digests a voucher and a close authorization sign. Amounts above 2^96 - 1 are INVALID. */
trp_err_t trp_voucher_digest(uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN],
                             const uint8_t channel_id[32], const uint8_t amount[TRP_U256_LEN],
                             uint8_t out[32]);
trp_err_t trp_close_authorization_digest(uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN],
                                         const uint8_t channel_id[32],
                                         const uint8_t amount[TRP_U256_LEN], uint8_t out[32]);

/* What a Tempo session challenge offers. */
typedef struct {
    uint8_t price[TRP_U256_LEN];             /* per unit, base units (`amount`) */
    int has_suggested_deposit;
    uint8_t suggested_deposit[TRP_U256_LEN];
    uint8_t currency[TRP_ADDRESS_LEN];
    uint8_t recipient[TRP_ADDRESS_LEN];      /* the payee */
    uint8_t escrow[TRP_ADDRESS_LEN];
    uint8_t operator_[TRP_ADDRESS_LEN];      /* zero when the server names none */
    uint64_t chain_id;                       /* 4217 when absent, per the session spec */
    int fee_payer;
    uint64_t expires;                        /* 0 if none */
} trp_session_request;

/* TRP_ERR_UNSUPPORTED for v1 (contract-backed) challenges and for other methods or intents. */
trp_err_t trp_session_request_parse(const trp_challenge *challenge, trp_session_request *out);

/* The client's view of an open channel. Keep it for the life of the session. */
typedef struct {
    trp_channel_descriptor descriptor;
    uint8_t channel_id[32];
    uint8_t escrow[TRP_ADDRESS_LEN];
    uint64_t chain_id;
    uint8_t deposit[TRP_U256_LEN];    /* total deposited */
    uint8_t cumulative[TRP_U256_LEN]; /* highest voucher signed so far */
} trp_session;

/*
 * Open a channel: deposit `deposit` (checked against options->policy, which
 * also limits token, recipient and chain), and write the `open` credential
 * with the initial voucher for one unit (the price). `salt` must be 32 fresh random bytes.
 * options->approve is not used here.
 *
 * Buffers for every session call: `work` 8 KB (open and top-up use about
 * 6.5 KB, voucher and close 4.5 KB) and `out` 4 KB, measured with a
 * 43-character challenge id; longer challenge fields add about 4/3 of their
 * length to `out`.
 */
trp_err_t trp_session_open(const trp_challenge *challenge, const trp_charge_options *options,
                           const uint8_t deposit[TRP_U256_LEN], const uint8_t salt[32],
                           trp_session *session, char *out, size_t out_cap, uint8_t *work,
                           size_t work_cap);

/*
 * Authorize `cumulative` in total (not an increment): it must not go down,
 * nor past the deposit. Writes a `voucher` credential for `challenge`.
 */
trp_err_t trp_session_voucher(trp_session *session, const trp_challenge *challenge,
                              const trp_signer *signer, const uint8_t cumulative[TRP_U256_LEN],
                              char *out, size_t out_cap, uint8_t *work, size_t work_cap);

/* Add `additional` to the deposit (checked against the policy) with a `topUp` credential. */
trp_err_t trp_session_top_up(trp_session *session, const trp_challenge *challenge,
                             const trp_charge_options *options,
                             const uint8_t additional[TRP_U256_LEN], char *out, size_t out_cap,
                             uint8_t *work, size_t work_cap);

/* Ask the server to settle the last voucher and close the channel. */
trp_err_t trp_session_close(trp_session *session, const trp_challenge *challenge,
                            const trp_signer *signer, char *out, size_t out_cap, uint8_t *work,
                            size_t work_cap);

#ifdef __cplusplus
}
#endif

#endif

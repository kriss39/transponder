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
    int has_min_voucher_delta;               /* the server's smallest voucher raise, if it says */
    uint8_t min_voucher_delta[TRP_U256_LEN];
} trp_session_request;

/* TRP_ERR_UNSUPPORTED for v1 (contract-backed) challenges and for other methods or intents. */
trp_err_t trp_session_request_parse(const trp_challenge *challenge, trp_session_request *out);

/* The client's view of an open channel. Keep it for the life of the session. */
typedef struct {
    trp_channel_descriptor descriptor;
    uint8_t channel_id[32];
    uint8_t escrow[TRP_ADDRESS_LEN];
    uint64_t chain_id;
    uint8_t deposit[TRP_U256_LEN];        /* total deposit the server has accepted */
    uint8_t pending_top_up[TRP_U256_LEN]; /* signed, not yet confirmed; zero when none */
    uint8_t cumulative[TRP_U256_LEN];     /* highest voucher signed so far */
    int closed;                           /* closed, or not usable: no more vouchers */
    uint64_t tx_valid_before;             /* valid_before of the last open or top-up signed */
} trp_session;

/*
 * Open a channel: deposit `deposit` (checked against options->policy, which
 * also limits token, recipient and chain, and then options->approve), and
 * write the `open` credential with the initial voucher for one unit (the
 * price). `salt` must be 32 fresh random bytes. For sessions the policy's
 * max_amount limits the channel's whole deposit, top-ups included.
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
 * nor past the confirmed deposit, and a raise must be at least the server's
 * minVoucherDelta. `signer` must be the channel's key, and the channel not
 * closed. Writes a `voucher` credential for `challenge`. The same amount
 * again is allowed (a retry); the server treats it as already accepted.
 */
trp_err_t trp_session_voucher(trp_session *session, const trp_challenge *challenge,
                              const trp_signer *signer, const uint8_t cumulative[TRP_U256_LEN],
                              char *out, size_t out_cap, uint8_t *work, size_t work_cap);

/*
 * Add `additional` to the deposit with a `topUp` credential, after the
 * policy (on the new total) and approve. The amount stays pending: call
 * trp_session_top_up_confirmed once the server accepts it (a 2xx), and only
 * then sign vouchers against it. Only one top-up may be pending.
 */
trp_err_t trp_session_top_up(trp_session *session, const trp_challenge *challenge,
                             const trp_charge_options *options,
                             const uint8_t additional[TRP_U256_LEN], char *out, size_t out_cap,
                             uint8_t *work, size_t work_cap);

/* The server accepted the pending top-up: count it in the deposit. */
void trp_session_top_up_confirmed(trp_session *session);

/*
 * The server refused the pending top-up: forget it. Only when it surely did
 * not reach the chain (an error response). If the response was lost, the
 * transaction may have been broadcast: resend the same credential, or read
 * the channel's deposit, rather than signing a new top-up.
 */
void trp_session_top_up_failed(trp_session *session);

/* Ask the server to settle the last voucher and close the channel. */
trp_err_t trp_session_close(trp_session *session, const trp_challenge *challenge,
                            const trp_signer *signer, char *out, size_t out_cap, uint8_t *work,
                            size_t work_cap);

/*
 * Keeping a session across restarts. A device that reboots mid-session
 * would otherwise lose the channel and its deposit stays locked until the
 * server closes it. Save the session to flash after every call that signs
 * (open, voucher, top-up, close) and before the credential is sent, and
 * after top_up_confirmed or _failed: then the saved cumulative is never
 * below what the server holds. After a restart, load it and sync it with
 * the chain before signing again.
 */
#define TRP_SESSION_STATE_LEN 338
#define TRP_SESSION_SYNC_MARGIN 60

/* Serialize `session` (versioned, with a checksum) for flash. */
void trp_session_save(const trp_session *session, uint8_t out[TRP_SESSION_STATE_LEN]);

/* Restore a saved session. INVALID for anything trp_session_save did not write, or that was corrupted. */
trp_err_t trp_session_load(trp_session *session, const uint8_t *state, size_t len);

/*
 * The JSON-RPC request body that reads the channel from the escrow:
 * eth_call of getChannelState(channelId) at "latest". POST it to any Tempo
 * RPC endpoint and pass the response to trp_session_sync.
 */
trp_err_t trp_session_state_request(const trp_session *session, char *out, size_t out_cap);

/*
 * Bring `session` in line with the chain, from the JSON-RPC response to
 * trp_session_state_request. `now` is Unix time.
 *
 * - The chain's deposit replaces the session's. A pending top-up that the
 *   deposit includes is confirmed; one that is missing once its transaction
 *   has expired failed.
 * - A channel with no deposit (closed, or its open never landed) or with a
 *   close request is marked closed: open a new one.
 * - If the server has settled more than the saved cumulative, the
 *   cumulative rises to it.
 *
 * TRP_ERR_PENDING, with the session unchanged, while the last open or
 * top-up could still land: until TRP_SESSION_SYNC_MARGIN seconds after its
 * tx_valid_before, which is at most 25 seconds after signing (the margin
 * covers RPC nodes that lag behind). Ask again after that. INVALID for an RPC error or a malformed
 * result.
 */
trp_err_t trp_session_sync(trp_session *session, const char *response, size_t len, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif

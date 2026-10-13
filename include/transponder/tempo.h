#ifndef TRANSPONDER_TEMPO_H
#define TRANSPONDER_TEMPO_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tempo transactions (EIP-2718 type 0x76) for MPP `charge` payments.
 * Byte layout and signing rules are in docs/DESIGN.md; the tests compare
 * every output with ox, the library the reference SDK uses.
 */

#define TRP_ADDRESS_LEN 20
#define TRP_U256_LEN 32
#define TRP_MEMO_LEN 32
#define TRP_P256_PUBKEY_LEN 64 /* x || y */
#define TRP_P256_SIGNATURE_LEN 130
#define TRP_TRANSFER_WITH_MEMO_LEN 100

/* A decimal string ("1000") as a 32-byte big-endian integer. Digits only. */
trp_err_t trp_u256_from_decimal(const char *s, size_t len, uint8_t out[TRP_U256_LEN]);

/*
 * The 32-byte MPP attribution memo the SDKs put on every payment:
 *   keccak256("mpp")[0..4] || 0x01 || keccak256(server_id)[0..10]
 *   || keccak256(client_id)[0..10] (zeros if absent) || keccak256(challenge_id)[0..7]
 * `server_id` is the challenge realm. `client_id` may have a NULL ptr.
 */
void trp_mpp_attribution_memo(trp_str server_id, trp_str client_id, trp_str challenge_id,
                              uint8_t out[TRP_MEMO_LEN]);

/* Calldata for TIP-20 transferWithMemo(address to, uint256 amount, bytes32 memo). */
void trp_tempo_transfer_with_memo(const uint8_t to[TRP_ADDRESS_LEN],
                                  const uint8_t amount[TRP_U256_LEN],
                                  const uint8_t memo[TRP_MEMO_LEN],
                                  uint8_t out[TRP_TRANSFER_WITH_MEMO_LEN]);

/* One call in a batch. Its value is always zero: payments move TIP-20 tokens. */
typedef struct {
    const uint8_t *to; /* TRP_ADDRESS_LEN bytes */
    const uint8_t *data;
    size_t data_len;
} trp_tempo_call;

/*
 * A Tempo transaction with an expiring nonce (nonce_key = 2^256 - 1,
 * nonce = 0), as the reference SDK uses for charges. Replay protection
 * comes from `valid_before`, so no nonce has to be read from the chain.
 */
typedef struct {
    uint64_t chain_id;
    uint64_t max_priority_fee_per_gas;
    uint64_t max_fee_per_gas;
    uint64_t gas_limit;
    const trp_tempo_call *calls; /* at least one */
    size_t call_count;
    uint64_t valid_before; /* unix seconds, required */
    uint64_t valid_after;  /* unix seconds, 0 for none */
    int fee_payer;         /* non-zero: the server sponsors fees and picks the fee token */
    const uint8_t *fee_token; /* TRP_ADDRESS_LEN bytes, or NULL; ignored when fee_payer is set */
} trp_tempo_tx;

/*
 * The hash the sender signs: keccak256(0x76 || rlp(fields)). `buf` is
 * working space for the RLP encoding (300 bytes covers one transfer).
 */
trp_err_t trp_tempo_sender_hash(const trp_tempo_tx *tx, uint8_t *buf, size_t buf_cap,
                                uint8_t out[32]);

/* What an access key signs for Keychain V2: keccak256(0x04 || sender_hash || owner). */
void trp_tempo_keychain_digest(const uint8_t sender_hash[32], const uint8_t owner[TRP_ADDRESS_LEN],
                               uint8_t out[32]);

/*
 * The 130-byte P-256 signature: 0x01 || r || s || pub_x || pub_y || pre_hash.
 * `s` is normalized to the low half of the curve order, which Tempo
 * requires; secure elements do not always produce it. Set `pre_hash` when
 * the signer signed SHA-256(digest) rather than the digest itself (Web
 * Crypto, Apple CryptoKit); Tempo then hashes the digest the same way
 * before verifying.
 */
trp_err_t trp_p256_signature(const uint8_t r[32], const uint8_t s[32],
                             const uint8_t public_key[TRP_P256_PUBKEY_LEN], int pre_hash,
                             uint8_t out[TRP_P256_SIGNATURE_LEN]);

/* Keychain V2 wrapper: 0x04 || owner || inner signature. */
trp_err_t trp_keychain_signature(const uint8_t owner[TRP_ADDRESS_LEN], const uint8_t *inner,
                                 size_t inner_len, uint8_t *out, size_t out_cap, size_t *out_len);

/* The signed transaction: 0x76 || rlp([fields..., signature]). */
trp_err_t trp_tempo_serialize(const trp_tempo_tx *tx, const uint8_t *signature, size_t signature_len,
                              uint8_t *out, size_t out_cap, size_t *out_len);

/* Address of a P-256 key: the last 20 bytes of keccak256(x || y). */
void trp_p256_address(const uint8_t public_key[TRP_P256_PUBKEY_LEN], uint8_t out[TRP_ADDRESS_LEN]);

#ifdef __cplusplus
}
#endif

#endif

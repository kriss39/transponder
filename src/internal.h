#ifndef TRANSPONDER_INTERNAL_H
#define TRANSPONDER_INTERNAL_H

/* Not part of the public API. */

#include "transponder/keccak.h"

/*
 * FIPS-202 SHA3-256 on the same sponge as Keccak-256; only the padding
 * byte differs. Used by the tests to check the permutation against an
 * independent implementation (Python's hashlib).
 */
void trp__sha3_256_final(trp_keccak_ctx *ctx, uint8_t out[TRP_KECCAK256_LEN]);

/* Write code point `cp` as UTF-8 into `out` (up to 4 bytes); returns the byte count, 0 if invalid. */
size_t trp__utf8_put(uint32_t cp, char out[4]);

/* Value of one hex digit, or -1. */
int trp__hex_nibble(char c);

/* ---- support.c: helpers shared by the charge and session flows ---------- */

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/json.h"
#include "transponder/tempo.h"

#define TRP__MAX_FIELD 80 /* longest request string read: a 0x-prefixed bytes32 or a uint256 */
#define TRP__DID_MAX 80   /* "did:pkh:eip155:" + chain id + ":" + 42-char address + NUL */

typedef struct {
    uint8_t *p;
    size_t left;
} trp__carver;

int trp__str_eq(trp_str s, const char *lit);
int trp__is_zero(const uint8_t *b, size_t n);
size_t trp__u64_to_dec(uint64_t v, char out[21]);
void *trp__take(trp__carver *c, size_t n);

/* Request fields. NOT_FOUND when absent; INVALID when present but malformed. */
trp_err_t trp__json_string(const trp_json *obj, const char *key, char *buf, size_t cap, size_t *len);
trp_err_t trp__json_hex(const trp_json *obj, const char *key, uint8_t *out, size_t n);
trp_err_t trp__json_u256(const trp_json *obj, const char *key, uint8_t out[32]);

/* now + TRP_CHARGE_MAX_VALIDITY, capped by the challenge's `expires`; INVALID if it already expired. */
trp_err_t trp__valid_before(const trp_challenge *ch, uint64_t now, uint64_t *out);

/* did:pkh:eip155:<chain>:<EIP-55 owner>; returns the length. */
size_t trp__did_pkh(uint64_t chain_id, const uint8_t owner[TRP_ADDRESS_LEN], char out[TRP__DID_MAX]);

/* A primitive P-256 signature over `digest` (pre_hash as the signer reports). */
trp_err_t trp__sign_p256(const trp_signer *signer, const uint8_t digest[32],
                         uint8_t out[TRP_P256_SIGNATURE_LEN]);

/* Sign a transaction as a Keychain V2 access key for `owner` and serialize it. */
trp_err_t trp__keychain_sign_tx(const trp_tempo_tx *tx, const uint8_t owner[TRP_ADDRESS_LEN],
                                const trp_signer *signer, uint8_t *rlp_buf, size_t rlp_cap,
                                uint8_t *envelope, size_t envelope_cap, size_t *envelope_len);

/* JSON values: "0x…" lowercase hex, an EIP-55 address, a decimal uint256 string. */
void trp__jw_hex(trp_json_writer *w, const uint8_t *bytes, size_t len);
void trp__jw_address(trp_json_writer *w, const uint8_t address[TRP_ADDRESS_LEN]);
void trp__jw_decimal(trp_json_writer *w, const uint8_t value[32]);

#endif

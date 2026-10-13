#include "transponder/tempo.h"

#include <string.h>

#include "transponder/keccak.h"
#include "transponder/rlp.h"

#define TX_TYPE 0x76
#define KEYCHAIN_V2 0x04
#define P256_TYPE 0x01

/* P-256 group order n, and n / 2 (rounded down), big-endian. */
static const uint8_t P256_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};
static const uint8_t P256_HALF_N[32] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
};

trp_err_t trp_u256_from_decimal(const char *s, size_t len, uint8_t out[TRP_U256_LEN])
{
    size_t i;
    int j;

    if (len == 0) return TRP_ERR_INVALID;
    memset(out, 0, TRP_U256_LEN);
    for (i = 0; i < len; i++) {
        unsigned carry;
        if (s[i] < '0' || s[i] > '9') return TRP_ERR_INVALID;
        carry = (unsigned)(s[i] - '0');
        /* out = out * 10 + digit */
        for (j = TRP_U256_LEN - 1; j >= 0; j--) {
            unsigned v = (unsigned)out[j] * 10u + carry;
            out[j] = (uint8_t)(v & 0xff);
            carry = v >> 8;
        }
        if (carry) return TRP_ERR_INVALID; /* does not fit in 256 bits */
    }
    return TRP_OK;
}

static void keccak_prefix(trp_str s, size_t n, uint8_t *out)
{
    uint8_t h[32];
    trp_keccak256((const uint8_t *)s.ptr, s.len, h);
    memcpy(out, h, n);
}

void trp_mpp_attribution_memo(trp_str server_id, trp_str client_id, trp_str challenge_id,
                              uint8_t out[TRP_MEMO_LEN])
{
    trp_str tag;

    tag.ptr = "mpp";
    tag.len = 3;
    memset(out, 0, TRP_MEMO_LEN);
    keccak_prefix(tag, 4, out);
    out[4] = 0x01;
    keccak_prefix(server_id, 10, out + 5);
    if (client_id.ptr) keccak_prefix(client_id, 10, out + 15);
    keccak_prefix(challenge_id, 7, out + 25);
}

void trp_tempo_transfer_with_memo(const uint8_t to[TRP_ADDRESS_LEN],
                                  const uint8_t amount[TRP_U256_LEN],
                                  const uint8_t memo[TRP_MEMO_LEN],
                                  uint8_t out[TRP_TRANSFER_WITH_MEMO_LEN])
{
    /* First 4 bytes of keccak256("transferWithMemo(address,uint256,bytes32)"). */
    static const uint8_t SELECTOR[4] = {0x95, 0x77, 0x7d, 0x59};

    memcpy(out, SELECTOR, 4);
    memset(out + 4, 0, 12);
    memcpy(out + 16, to, TRP_ADDRESS_LEN);
    memcpy(out + 36, amount, TRP_U256_LEN);
    memcpy(out + 68, memo, TRP_MEMO_LEN);
}

/* Fields 1-13 of the transaction, in order, as they appear in the sender hash. */
static void write_fields(trp_rlp_writer *w, const trp_tempo_tx *tx)
{
    static const uint8_t EXPIRING_NONCE_KEY[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    static const uint8_t FEE_PAYER_PLACEHOLDER = 0x00;
    size_t list, call, i;

    trp_rlp_uint64(w, tx->chain_id);
    trp_rlp_uint64(w, tx->max_priority_fee_per_gas);
    trp_rlp_uint64(w, tx->max_fee_per_gas);
    trp_rlp_uint64(w, tx->gas_limit);

    list = trp_rlp_list_begin(w);
    for (i = 0; i < tx->call_count; i++) {
        call = trp_rlp_list_begin(w);
        trp_rlp_bytes(w, tx->calls[i].to, TRP_ADDRESS_LEN);
        trp_rlp_uint64(w, 0); /* value */
        trp_rlp_bytes(w, tx->calls[i].data, tx->calls[i].data_len);
        trp_rlp_list_end(w, call);
    }
    trp_rlp_list_end(w, list);

    list = trp_rlp_list_begin(w); /* access_list: empty */
    trp_rlp_list_end(w, list);

    trp_rlp_uint_be(w, EXPIRING_NONCE_KEY, sizeof(EXPIRING_NONCE_KEY));
    trp_rlp_uint64(w, 0); /* nonce */
    trp_rlp_uint64(w, tx->valid_before);
    trp_rlp_uint64(w, tx->valid_after); /* zero encodes as 0x80, the same as "none" */

    if (tx->fee_payer) {
        /* The sender doesn't commit to a fee token; the sponsor fills it in. */
        trp_rlp_bytes(w, NULL, 0);
        trp_rlp_bytes(w, &FEE_PAYER_PLACEHOLDER, 1);
    } else {
        trp_rlp_bytes(w, tx->fee_token, tx->fee_token ? TRP_ADDRESS_LEN : 0);
        trp_rlp_bytes(w, NULL, 0); /* no fee payer signature */
    }

    list = trp_rlp_list_begin(w); /* aa_authorization_list: empty */
    trp_rlp_list_end(w, list);
    /* key_authorization: absent, so not encoded at all */
}

static trp_err_t check_tx(const trp_tempo_tx *tx)
{
    size_t i;

    if (tx->call_count == 0 || tx->calls == NULL || tx->valid_before == 0) return TRP_ERR_INVALID;
    for (i = 0; i < tx->call_count; i++)
        if (tx->calls[i].to == NULL || (tx->calls[i].data == NULL && tx->calls[i].data_len))
            return TRP_ERR_INVALID;
    return TRP_OK;
}

trp_err_t trp_tempo_sender_hash(const trp_tempo_tx *tx, uint8_t *buf, size_t buf_cap,
                                uint8_t out[32])
{
    trp_rlp_writer w;
    size_t list;
    trp_err_t err;

    if ((err = check_tx(tx)) != TRP_OK) return err;
    if (buf_cap < 1) return TRP_ERR_BUFFER;
    buf[0] = TX_TYPE;
    trp_rlp_init(&w, buf + 1, buf_cap - 1);
    list = trp_rlp_list_begin(&w);
    write_fields(&w, tx);
    trp_rlp_list_end(&w, list);
    if (w.err != TRP_OK) return w.err;
    trp_keccak256(buf, w.len + 1, out);
    return TRP_OK;
}

void trp_tempo_keychain_digest(const uint8_t sender_hash[32], const uint8_t owner[TRP_ADDRESS_LEN],
                               uint8_t out[32])
{
    trp_keccak_ctx ctx;
    const uint8_t version = KEYCHAIN_V2;

    trp_keccak256_init(&ctx);
    trp_keccak256_update(&ctx, &version, 1);
    trp_keccak256_update(&ctx, sender_hash, 32);
    trp_keccak256_update(&ctx, owner, TRP_ADDRESS_LEN);
    trp_keccak256_final(&ctx, out);
}

static int u256_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

/* out = a - b, for a >= b. */
static void u256_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    int i, borrow = 0;

    for (i = 31; i >= 0; i--) {
        int v = (int)a[i] - (int)b[i] - borrow;
        borrow = v < 0;
        out[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
}

static int u256_is_zero(const uint8_t a[32])
{
    int i;
    for (i = 0; i < 32; i++)
        if (a[i]) return 0;
    return 1;
}

trp_err_t trp_p256_signature(const uint8_t r[32], const uint8_t s[32],
                             const uint8_t public_key[TRP_P256_PUBKEY_LEN], int pre_hash,
                             uint8_t out[TRP_P256_SIGNATURE_LEN])
{
    if (u256_is_zero(r) || u256_is_zero(s) || u256_cmp(r, P256_N) >= 0 || u256_cmp(s, P256_N) >= 0)
        return TRP_ERR_INVALID;
    out[0] = P256_TYPE;
    memcpy(out + 1, r, 32);
    if (u256_cmp(s, P256_HALF_N) > 0) u256_sub(P256_N, s, out + 33);
    else memcpy(out + 33, s, 32);
    memcpy(out + 65, public_key, TRP_P256_PUBKEY_LEN);
    out[129] = pre_hash ? 1 : 0;
    return TRP_OK;
}

trp_err_t trp_keychain_signature(const uint8_t owner[TRP_ADDRESS_LEN], const uint8_t *inner,
                                 size_t inner_len, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (inner_len == 0) return TRP_ERR_INVALID;
    if (out_cap < 1 + TRP_ADDRESS_LEN + inner_len) return TRP_ERR_BUFFER;
    out[0] = KEYCHAIN_V2;
    memcpy(out + 1, owner, TRP_ADDRESS_LEN);
    memcpy(out + 1 + TRP_ADDRESS_LEN, inner, inner_len);
    *out_len = 1 + TRP_ADDRESS_LEN + inner_len;
    return TRP_OK;
}

trp_err_t trp_tempo_serialize(const trp_tempo_tx *tx, const uint8_t *signature, size_t signature_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    trp_rlp_writer w;
    size_t list;
    trp_err_t err;

    if ((err = check_tx(tx)) != TRP_OK) return err;
    if (signature == NULL || signature_len == 0) return TRP_ERR_INVALID;
    if (out_cap < 1) return TRP_ERR_BUFFER;
    out[0] = TX_TYPE;
    trp_rlp_init(&w, out + 1, out_cap - 1);
    list = trp_rlp_list_begin(&w);
    write_fields(&w, tx);
    trp_rlp_bytes(&w, signature, signature_len);
    trp_rlp_list_end(&w, list);
    if (w.err != TRP_OK) return w.err;
    *out_len = w.len + 1;
    return TRP_OK;
}

void trp_p256_address(const uint8_t public_key[TRP_P256_PUBKEY_LEN], uint8_t out[TRP_ADDRESS_LEN])
{
    uint8_t h[32];

    trp_keccak256(public_key, TRP_P256_PUBKEY_LEN, h);
    memcpy(out, h + 12, TRP_ADDRESS_LEN);
}

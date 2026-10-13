#include "test.h"

#include "transponder/keccak.h"
#include "transponder/tempo.h"
#include "tempo_vectors.h"

/* Decode a vector's hex string into `out`; returns the byte count. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (trp_hex_decode(hex, strlen(hex), out, cap, &n) != TRP_OK) {
        printf("  bad vector hex\n");
        return 0;
    }
    return n;
}

static trp_str s_of(const char *s)
{
    trp_str out;
    out.ptr = s;
    out.len = s ? strlen(s) : 0;
    return out;
}

static void test_vectors(void)
{
    /* The attribution inputs each vector was generated from (see gen.mjs). */
    static const char *const ATTRIBUTION[][3] = {
        {"api.example.com", NULL, "ch_abc123"},
        {"mpp.dev", "transponder", "x7Tg2pLqR9mKvNwY3hBcZa"},
    };
    uint8_t pub[64], owner[20], token[20], recipient[20], key_addr[20];
    size_t i;

    unhex(TV_PUBLIC_KEY, pub, sizeof(pub));
    unhex(TV_OWNER, owner, sizeof(owner));
    unhex(TV_TOKEN, token, sizeof(token));
    unhex(TV_RECIPIENT, recipient, sizeof(recipient));

    trp_p256_address(pub, key_addr);
    CHECK_HEX(key_addr, 20, TV_KEY_ADDRESS);

    for (i = 0; i < sizeof(TEMPO_VECTORS) / sizeof(TEMPO_VECTORS[0]); i++) {
        const tempo_vector *v = &TEMPO_VECTORS[i];
        uint8_t amount[32], memo[32], calldata[100], hash[32], digest[32], r[32], s[32];
        uint8_t p256[130], keychain[160], buf[512], envelope[512];
        size_t keychain_len = 0, envelope_len = 0;
        trp_tempo_call call;
        trp_tempo_tx tx;

        CHECK(trp_u256_from_decimal(v->amount_decimal, strlen(v->amount_decimal), amount) == TRP_OK);
        trp_mpp_attribution_memo(s_of(ATTRIBUTION[i][0]), s_of(ATTRIBUTION[i][1]),
                                 s_of(ATTRIBUTION[i][2]), memo);
        CHECK_HEX(memo, 32, v->memo);

        trp_tempo_transfer_with_memo(recipient, amount, memo, calldata);
        CHECK_HEX(calldata, 100, v->calldata);

        call.to = token;
        call.data = calldata;
        call.data_len = sizeof(calldata);
        memset(&tx, 0, sizeof(tx));
        tx.chain_id = v->chain_id;
        tx.max_priority_fee_per_gas = v->max_priority_fee_per_gas;
        tx.max_fee_per_gas = v->max_fee_per_gas;
        tx.gas_limit = v->gas;
        tx.calls = &call;
        tx.call_count = 1;
        tx.valid_before = v->valid_before;
        tx.valid_after = v->has_valid_after ? v->valid_after : 0;
        tx.fee_payer = v->fee_payer;
        tx.fee_token = v->fee_payer ? NULL : token;

        CHECK(trp_tempo_sender_hash(&tx, buf, sizeof(buf), hash) == TRP_OK);
        CHECK_HEX(hash, 32, v->sender_hash);

        trp_tempo_keychain_digest(hash, owner, digest);
        CHECK_HEX(digest, 32, v->keychain_digest);

        unhex(v->sig_r, r, sizeof(r));
        unhex(v->sig_s, s, sizeof(s));
        CHECK(trp_p256_signature(r, s, pub, p256) == TRP_OK);
        CHECK(trp_keychain_signature(owner, p256, sizeof(p256), keychain, sizeof(keychain),
                                     &keychain_len) == TRP_OK);
        CHECK(keychain_len == 151);
        CHECK(trp_tempo_serialize(&tx, keychain, keychain_len, envelope, sizeof(envelope),
                                  &envelope_len) == TRP_OK);
        CHECK_HEX(envelope, envelope_len, v->envelope);

        /* Working space that is too small is reported. */
        CHECK(trp_tempo_sender_hash(&tx, buf, 100, hash) == TRP_ERR_BUFFER);
        CHECK(trp_tempo_serialize(&tx, keychain, keychain_len, envelope, envelope_len - 1,
                                  &envelope_len) == TRP_ERR_BUFFER);
    }
}

static void test_signature_rules(void)
{
    static const uint8_t N[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    uint8_t pub[64], r[32], s[32], high_s[32], zero[32] = {0};
    uint8_t low_sig[130], high_sig[130];
    int i, borrow = 0;

    unhex(TV_PUBLIC_KEY, pub, sizeof(pub));
    unhex(TEMPO_VECTORS[0].sig_r, r, sizeof(r));
    unhex(TEMPO_VECTORS[0].sig_s, s, sizeof(s));

    /* (r, n - s) is the same signature; it must encode to the low-s form. */
    for (i = 31; i >= 0; i--) {
        int d = (int)N[i] - (int)s[i] - borrow;
        borrow = d < 0;
        high_s[i] = (uint8_t)(d + (borrow ? 256 : 0));
    }
    CHECK(trp_p256_signature(r, s, pub, low_sig) == TRP_OK);
    CHECK(trp_p256_signature(r, high_s, pub, high_sig) == TRP_OK);
    CHECK(memcmp(low_sig, high_sig, sizeof(low_sig)) == 0);
    CHECK(low_sig[0] == 0x01 && low_sig[129] == 0x00);

    CHECK(trp_p256_signature(zero, s, pub, low_sig) == TRP_ERR_INVALID);
    CHECK(trp_p256_signature(r, zero, pub, low_sig) == TRP_ERR_INVALID);
    CHECK(trp_p256_signature(r, N, pub, low_sig) == TRP_ERR_INVALID);
}

static void test_helpers(void)
{
    uint8_t out[32], h[32];
    const char *max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const char *over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    const char *sig = "transferWithMemo(address,uint256,bytes32)";
    trp_tempo_tx tx;

    CHECK(trp_u256_from_decimal("0", 1, out) == TRP_OK);
    CHECK_HEX(out, 32, "0000000000000000000000000000000000000000000000000000000000000000");
    CHECK(trp_u256_from_decimal("1000", 4, out) == TRP_OK);
    CHECK_HEX(out, 32, "00000000000000000000000000000000000000000000000000000000000003e8");
    CHECK(trp_u256_from_decimal(max, strlen(max), out) == TRP_OK);
    CHECK_HEX(out, 32, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CHECK(trp_u256_from_decimal(over, strlen(over), out) == TRP_ERR_INVALID);
    CHECK(trp_u256_from_decimal("", 0, out) == TRP_ERR_INVALID);
    CHECK(trp_u256_from_decimal("12a", 3, out) == TRP_ERR_INVALID);
    CHECK(trp_u256_from_decimal("-1", 2, out) == TRP_ERR_INVALID);

    /* The selector hard-coded in tempo.c, recomputed. */
    trp_keccak256((const uint8_t *)sig, strlen(sig), h);
    CHECK_HEX(h, 4, TV_TRANSFER_WITH_MEMO_SELECTOR);

    /* A transaction needs a call and an expiry. */
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = 42431;
    tx.valid_before = 1;
    CHECK(trp_tempo_sender_hash(&tx, out, sizeof(out), h) == TRP_ERR_INVALID);
}

void test_tempo(void)
{
    test_vectors();
    test_signature_rules();
    test_helpers();
}

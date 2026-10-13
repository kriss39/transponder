#include "test.h"

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "tempo_vectors.h"

/*
 * Stands in for a secure element: it checks it was asked to sign the digest
 * ox computed, then returns the signature ox produced for it.
 */
typedef struct {
    uint8_t expected_digest[32];
    uint8_t r[32];
    uint8_t s[32];
    int calls;
    int fail;
} fake_key;

static trp_err_t fake_sign(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    fake_key *k = (fake_key *)ctx;
    k->calls++;
    if (k->fail || memcmp(digest, k->expected_digest, 32) != 0) return TRP_ERR_CRYPTO;
    memcpy(r, k->r, 32);
    memcpy(s, k->s, 32);
    return TRP_OK;
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    trp_hex_decode(hex, strlen(hex), out, cap, &n);
    return n;
}

static char scratch[4096];
static uint8_t work[4096];
static char header[4096];

static void setup(trp_signer *signer, fake_key *key, uint8_t owner[20], uint8_t token[20],
                  trp_charge_options *opt)
{
    memset(key, 0, sizeof(*key));
    memset(opt, 0, sizeof(*opt));
    signer->sign_digest = fake_sign;
    signer->ctx = key;
    unhex(TV_PUBLIC_KEY, signer->public_key, sizeof(signer->public_key));
    unhex(TV_OWNER, owner, 20);
    unhex(TV_TOKEN, token, 20);
    opt->owner = owner;
    opt->signer = signer;
}

static void test_vectors(void)
{
    size_t i;

    for (i = 0; i < sizeof(CHARGE_VECTORS) / sizeof(CHARGE_VECTORS[0]); i++) {
        const charge_vector *v = &CHARGE_VECTORS[i];
        trp_signer signer;
        fake_key key;
        uint8_t owner[20], token[20];
        trp_charge_options opt;
        trp_challenge ch;
        trp_err_t err;

        setup(&signer, &key, owner, token, &opt);
        unhex(v->digest, key.expected_digest, 32);
        unhex(v->sig_r, key.r, 32);
        unhex(v->sig_s, key.s, 32);
        opt.now = v->now;
        opt.valid_after = v->valid_after;
        opt.gas_limit = v->gas;
        opt.max_fee_per_gas = v->max_fee_per_gas;
        opt.max_priority_fee_per_gas = v->max_priority_fee_per_gas;
        opt.fee_token = v->has_fee_token ? token : NULL;
        if (v->client_id) {
            opt.client_id.ptr = v->client_id;
            opt.client_id.len = strlen(v->client_id);
        }

        CHECK(trp_challenge_parse(v->wire, strlen(v->wire), &ch, scratch, sizeof(scratch)) == TRP_OK);
        err = trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work));
        trp_test_checks++;
        if (err != TRP_OK || strcmp(header, v->credential) != 0) {
            trp_test_failures++;
            printf("  FAIL charge/%s (err %d, signer calls %d)\n", v->name, (int)err, key.calls);
        }
        CHECK(key.calls == 1);
    }
}

/* A challenge for `request_json`, so the error paths can be exercised. */
static trp_err_t charge_with(const char *request_json, const char *expires, trp_charge_options *opt)
{
    char req[512], wire[1024];
    trp_challenge ch;
    trp_err_t err;

    if (trp_base64url_encode((const uint8_t *)request_json, strlen(request_json), req, sizeof(req)) != TRP_OK)
        return TRP_ERR_BUFFER;
    snprintf(wire, sizeof(wire),
             "Payment id=\"t\", realm=\"r\", method=\"tempo\", intent=\"charge\", request=\"%s\"%s%s%s",
             req, expires ? ", expires=\"" : "", expires ? expires : "", expires ? "\"" : "");
    if ((err = trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch))) != TRP_OK) return err;
    return trp_tempo_charge(&ch, opt, header, sizeof(header), work, sizeof(work));
}

static void test_errors(void)
{
    const char *base = "{\"amount\":\"5\",\"currency\":\"0x20c0000000000000000000000000000000000000\","
                       "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\"";
    char json[512];
    trp_signer signer;
    fake_key key;
    uint8_t owner[20], token[20];
    trp_charge_options opt;

    setup(&signer, &key, owner, token, &opt);
    opt.now = 1791972000u;
    opt.gas_limit = 100000;
    opt.default_chain_id = 42431;

    /* The fake key refuses any digest it wasn't told about: the happy path fails at signing. */
    snprintf(json, sizeof(json), "%s}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_CRYPTO);

    /* No chainId in the request and no default. */
    opt.default_chain_id = 0;
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_INVALID);
    opt.default_chain_id = 42431;

    CHECK(charge_with(json, "2026-10-14T09:59:59Z", &opt) == TRP_ERR_INVALID); /* expired */
    CHECK(charge_with(json, "not a date", &opt) == TRP_ERR_INVALID);

    snprintf(json, sizeof(json), "%s,\"methodDetails\":{\"supportedModes\":[\"push\"]}}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_UNSUPPORTED);
    snprintf(json, sizeof(json), "%s,\"methodDetails\":{\"splits\":[{\"amount\":\"1\"}]}}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_UNSUPPORTED);
    snprintf(json, sizeof(json), "%s,\"methodDetails\":{\"splits\":[]}}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_CRYPTO); /* empty splits are fine */
    snprintf(json, sizeof(json), "%s,\"methodDetails\":{\"memo\":\"0x1234\"}}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_INVALID);
    snprintf(json, sizeof(json), "%s,\"methodDetails\":{\"feePayer\":\"yes\"}}", base);
    CHECK(charge_with(json, NULL, &opt) == TRP_ERR_INVALID);

    CHECK(charge_with("{\"amount\":\"0\",\"currency\":\"0x20c0000000000000000000000000000000000000\","
                      "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\"}",
                      NULL, &opt) == TRP_ERR_UNSUPPORTED);
    CHECK(charge_with("{\"amount\":\"5\",\"currency\":\"0x20c0\","
                      "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\"}",
                      NULL, &opt) == TRP_ERR_INVALID);
    CHECK(charge_with("{\"amount\":5,\"currency\":\"0x20c0000000000000000000000000000000000000\","
                      "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\"}",
                      NULL, &opt) == TRP_ERR_INVALID);

    /* Not a Tempo charge. */
    {
        const char *w = "Payment id=\"t\", realm=\"r\", method=\"stripe\", intent=\"charge\", request=\"e30\"";
        trp_challenge ch;
        CHECK(trp_challenge_parse(w, strlen(w), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work)) ==
              TRP_ERR_UNSUPPORTED);
    }
}

static void test_buffers(void)
{
    const charge_vector *v = &CHARGE_VECTORS[0];
    trp_signer signer;
    fake_key key;
    uint8_t owner[20], token[20];
    trp_charge_options opt;
    trp_challenge ch;

    setup(&signer, &key, owner, token, &opt);
    unhex(v->digest, key.expected_digest, 32);
    unhex(v->sig_r, key.r, 32);
    unhex(v->sig_s, key.s, 32);
    opt.now = v->now;
    opt.valid_after = v->valid_after;
    opt.gas_limit = v->gas;
    opt.max_fee_per_gas = v->max_fee_per_gas;
    opt.client_id.ptr = v->client_id;
    opt.client_id.len = strlen(v->client_id);

    CHECK(trp_challenge_parse(v->wire, strlen(v->wire), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, 1000) == TRP_ERR_BUFFER);
    CHECK(trp_tempo_charge(&ch, &opt, header, 100, work, sizeof(work)) == TRP_ERR_BUFFER);
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work)) == TRP_OK);

    key.fail = 1;
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work)) == TRP_ERR_CRYPTO);
}

static void test_helpers(void)
{
    /* Mixed-case addresses from the EIP-55 specification. */
    static const char *const EIP55[] = {
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    };
    uint8_t addr[20];
    char out[43];
    uint64_t t;
    size_t i;

    for (i = 0; i < sizeof(EIP55) / sizeof(EIP55[0]); i++) {
        unhex(EIP55[i], addr, sizeof(addr));
        trp_address_checksum(addr, out);
        CHECK(strcmp(out, EIP55[i]) == 0);
    }

    CHECK(trp_parse_rfc3339("1970-01-01T00:00:00Z", 20, &t) == TRP_OK && t == 0);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00Z", 20, &t) == TRP_OK && t == 1791972000u);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00.123Z", 24, &t) == TRP_OK && t == 1791972000u);
    CHECK(trp_parse_rfc3339("2026-10-14T12:30:00+02:30", 25, &t) == TRP_OK && t == 1791972000u);
    CHECK(trp_parse_rfc3339("2024-02-29T00:00:00Z", 20, &t) == TRP_OK && t == 1709164800u);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00", 19, &t) == TRP_ERR_INVALID);
    CHECK(trp_parse_rfc3339("2026-13-14T10:00:00Z", 20, &t) == TRP_ERR_INVALID);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00Zjunk", 24, &t) == TRP_ERR_INVALID);
}

void test_charge(void)
{
    test_vectors();
    test_errors();
    test_buffers();
    test_helpers();
}

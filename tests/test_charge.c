#include "test.h"

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/json.h"
#include "tempo_vectors.h"

/*
 * Stands in for a secure element. In checking mode it signs only the digest
 * ox computed and returns ox's signature for it; in stamp mode it returns a
 * fixed valid-looking signature for anything, to reach later stages.
 */
typedef struct {
    uint8_t expected_digest[32];
    uint8_t r[32];
    uint8_t s[32];
    int calls;
    int fail;
    int stamp;
} fake_key;

static trp_err_t fake_sign(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    fake_key *k = (fake_key *)ctx;
    k->calls++;
    if (k->stamp) {
        memset(r, 0x11, 32);
        memset(s, 0x22, 32);
        return TRP_OK;
    }
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
static uint8_t work[8192];
static char header[8192];

/* Allows anything up to 10^12 base units on any token, recipient and chain. */
static trp_spend_policy open_policy;

static void setup(trp_signer *signer, fake_key *key, uint8_t owner[20], uint8_t token[20],
                  trp_charge_options *opt)
{
    memset(key, 0, sizeof(*key));
    memset(opt, 0, sizeof(*opt));
    memset(signer, 0, sizeof(*signer));
    memset(&open_policy, 0, sizeof(open_policy));
    trp_u256_from_decimal("1000000000000", 13, open_policy.max_amount);
    signer->sign_digest = fake_sign;
    signer->ctx = key;
    unhex(TV_PUBLIC_KEY, signer->public_key, sizeof(signer->public_key));
    unhex(TV_OWNER, owner, 20);
    unhex(TV_TOKEN, token, 20);
    opt->owner = owner;
    opt->signer = signer;
    opt->policy = &open_policy;
}

static void test_vectors(void)
{
    size_t i;

    for (i = 0; i < sizeof(CHARGE_VECTORS) / sizeof(CHARGE_VECTORS[0]); i++) {
        const charge_vector *v = &CHARGE_VECTORS[i];
        trp_signer signer;
        fake_key key;
        uint8_t owner[20], token[20], want_hash[32];
        trp_charge_options opt;
        trp_charge_result result;
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
        err = trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work), &result);
        trp_test_checks++;
        if (err != TRP_OK || strcmp(header, v->credential) != 0) {
            trp_test_failures++;
            printf("  FAIL charge/%s (err %d, signer calls %d)\n", v->name, (int)err, key.calls);
        }
        CHECK(key.calls == 1);
        unhex(v->tx_hash, want_hash, 32);
        CHECK(memcmp(result.tx_hash, want_hash, 32) == 0);
    }
}

/* A challenge for `request_json`, so the error paths can be exercised. */
static trp_err_t charge_with(const char *request_json, const char *expires, trp_charge_options *opt)
{
    char req[1024], wire[2048];
    trp_challenge ch;
    trp_err_t err;

    if (trp_base64url_encode((const uint8_t *)request_json, strlen(request_json), req, sizeof(req)) != TRP_OK)
        return TRP_ERR_BUFFER;
    snprintf(wire, sizeof(wire),
             "Payment id=\"t\", realm=\"r\", method=\"tempo\", intent=\"charge\", request=\"%s\"%s%s%s",
             req, expires ? ", expires=\"" : "", expires ? expires : "", expires ? "\"" : "");
    if ((err = trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch))) != TRP_OK) return err;
    return trp_tempo_charge(&ch, opt, header, sizeof(header), work, sizeof(work), NULL);
}

#define TOKEN "0x20c0000000000000000000000000000000000000"
#define RECIPIENT "0x742d35cc6634c0532925a3b844bc9e7595f8fe00"
#define BASE "{\"amount\":\"5\",\"currency\":\"" TOKEN "\",\"recipient\":\"" RECIPIENT "\""

static trp_err_t deny_all(void *ctx, const trp_challenge *ch, const trp_charge_request *req)
{
    (void)ch;
    (void)req;
    ++*(int *)ctx;
    return TRP_ERR_DENIED;
}

static void test_policy(void)
{
    trp_signer signer;
    fake_key key;
    uint8_t owner[20], token[20], other[20] = {0x99};
    trp_charge_options opt;
    trp_spend_policy policy;
    uint64_t mainnet = TRP_TEMPO_MAINNET;
    int asked = 0;

    setup(&signer, &key, owner, token, &opt);
    opt.now = 1791972000u;
    opt.gas_limit = 100000;
    opt.max_fee_per_gas = 1;
    key.stamp = 1;

    /* Within the policy: it signs. */
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_OK);
    CHECK(key.calls == 1);

    /* Over the limit, a token or recipient not listed, or the wrong chain: no signature. */
    policy = open_policy;
    trp_u256_from_decimal("4", 1, policy.max_amount);
    opt.policy = &policy;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_DENIED);
    policy = open_policy;
    policy.tokens = (const uint8_t(*)[20])other;
    policy.token_count = 1;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_DENIED);
    policy = open_policy;
    policy.recipients = (const uint8_t(*)[20])other;
    policy.recipient_count = 1;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_DENIED);
    policy = open_policy;
    policy.chain_ids = &mainnet; /* the request names no chain: Moderato */
    policy.chain_id_count = 1;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_DENIED);
    CHECK(charge_with(BASE ",\"methodDetails\":{\"chainId\":4217}}", NULL, &opt) == TRP_OK);
    CHECK(key.calls == 2);

    /* A split to a recipient outside the list is refused too. */
    policy = open_policy;
    unhex(RECIPIENT, other, 20);
    policy.recipients = (const uint8_t(*)[20])other;
    policy.recipient_count = 1;
    CHECK(charge_with(BASE ",\"methodDetails\":{\"splits\":[{\"amount\":\"1\",\"recipient\":"
                           "\"0x1111111111111111111111111111111111111111\"}]}}",
                      NULL, &opt) == TRP_ERR_DENIED);
    CHECK(key.calls == 2);

    /* The approve callback has the last word. */
    opt.policy = &open_policy;
    opt.approve = deny_all;
    opt.approve_ctx = &asked;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_DENIED);
    CHECK(asked == 1 && key.calls == 2);
    opt.approve = NULL;

    /* No policy, or a zero limit, is a configuration error. */
    opt.policy = NULL;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_INVALID);
    memset(&policy, 0, sizeof(policy));
    opt.policy = &policy;
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_INVALID);
    CHECK(key.calls == 2);
}

static void test_errors(void)
{
    trp_signer signer;
    fake_key key;
    uint8_t owner[20], token[20];
    trp_charge_options opt;
    trp_charge_request req;
    trp_challenge ch;
    trp_json root, v;
    uint8_t decoded[4096];
    size_t n;
    char source[128];
    const char *w;

    setup(&signer, &key, owner, token, &opt);
    opt.now = 1791972000u;
    opt.gas_limit = 100000;
    opt.max_fee_per_gas = 1;

    /* The fake key refuses digests it was not told about. */
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_CRYPTO);
    CHECK(charge_with(BASE "}", "2026-10-14T09:59:59Z", &opt) == TRP_ERR_INVALID); /* expired */
    CHECK(charge_with(BASE "}", "not a date", &opt) == TRP_ERR_INVALID);
    CHECK(charge_with(BASE "}", "2026-02-30T10:00:00Z", &opt) == TRP_ERR_INVALID);

    CHECK(charge_with(BASE ",\"methodDetails\":{\"supportedModes\":[\"push\"]}}", NULL, &opt) == TRP_ERR_UNSUPPORTED);
    /* An escaped "pull" is still "pull". */
    CHECK(charge_with(BASE ",\"methodDetails\":{\"supportedModes\":[\"\\u0070ull\"]}}", NULL, &opt) == TRP_ERR_CRYPTO);
    CHECK(charge_with(BASE ",\"methodDetails\":{\"splits\":[]}}", NULL, &opt) == TRP_ERR_CRYPTO);
    CHECK(charge_with(BASE ",\"methodDetails\":{\"splits\":[{\"amount\":\"5\",\"recipient\":\"" RECIPIENT "\"}]}}",
                      NULL, &opt) == TRP_ERR_INVALID); /* nothing left for the primary */
    CHECK(charge_with(BASE ",\"methodDetails\":{\"splits\":[{\"amount\":\"0\",\"recipient\":\"" RECIPIENT "\"}]}}",
                      NULL, &opt) == TRP_ERR_INVALID);
    CHECK(charge_with("{\"amount\":\"9\",\"currency\":\"" TOKEN "\",\"recipient\":\"" RECIPIENT "\","
                      "\"methodDetails\":{\"splits\":["
                      "{\"amount\":\"1\",\"recipient\":\"" RECIPIENT "\"},{\"amount\":\"1\",\"recipient\":\"" RECIPIENT "\"},"
                      "{\"amount\":\"1\",\"recipient\":\"" RECIPIENT "\"},{\"amount\":\"1\",\"recipient\":\"" RECIPIENT "\"},"
                      "{\"amount\":\"1\",\"recipient\":\"" RECIPIENT "\"}]}}",
                      NULL, &opt) == TRP_ERR_UNSUPPORTED); /* more than TRP_MAX_SPLITS */
    CHECK(charge_with(BASE ",\"methodDetails\":{\"memo\":\"0x1234\"}}", NULL, &opt) == TRP_ERR_INVALID);
    CHECK(charge_with(BASE ",\"methodDetails\":{\"feePayer\":\"yes\"}}", NULL, &opt) == TRP_ERR_INVALID);
    CHECK(charge_with(BASE ",\"methodDetails\":{\"chainId\":0}}", NULL, &opt) == TRP_ERR_INVALID);
    CHECK(charge_with("{\"amount\":\"0\",\"currency\":\"" TOKEN "\",\"recipient\":\"" RECIPIENT "\"}", NULL, &opt) ==
          TRP_ERR_UNSUPPORTED);
    CHECK(charge_with("{\"amount\":\"5\",\"currency\":\"0x20c0\",\"recipient\":\"" RECIPIENT "\"}", NULL, &opt) ==
          TRP_ERR_INVALID);
    CHECK(charge_with("{\"amount\":5,\"currency\":\"" TOKEN "\",\"recipient\":\"" RECIPIENT "\"}", NULL, &opt) ==
          TRP_ERR_INVALID);

    /* Option checks. */
    opt.valid_after = opt.now + 100; /* after the transaction would expire */
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_INVALID);
    opt.valid_after = 0;
    opt.max_fee_per_gas = 0; /* the client pays fees but allows no fee */
    CHECK(charge_with(BASE "}", NULL, &opt) == TRP_ERR_INVALID);
    opt.max_fee_per_gas = 1;

    /* No chainId means Moderato, as the spec says. */
    w = "Payment id=\"t\", realm=\"r\", method=\"tempo\", intent=\"charge\", request=\"eyJhbW91bnQiOiIxIiwiY3VycmVuY3kiOiIweDIwYzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJyZWNpcGllbnQiOiIweDc0MmQzNWNjNjYzNGMwNTMyOTI1YTNiODQ0YmM5ZTc1OTVmOGZlMDAifQ\"";
    CHECK(trp_challenge_parse(w, strlen(w), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_charge_request_parse(&ch, &req) == TRP_OK && req.chain_id == TRP_TEMPO_MODERATO);

    /* The largest chain ID fits in the credential's source (once a 64-byte stack overflow). */
    key.stamp = 1;
    CHECK(charge_with(BASE ",\"methodDetails\":{\"chainId\":18446744073709551615}}", NULL, &opt) == TRP_OK);
    CHECK(trp_base64url_decode(header + 8, strlen(header + 8), decoded, sizeof(decoded), &n) == TRP_OK);
    CHECK(trp_json_parse((const char *)decoded, n, &root) == TRP_OK && trp_json_get(&root, "source", &v) == TRP_OK);
    CHECK(trp_json_get_string(&v, source, sizeof(source), NULL) == TRP_OK);
    CHECK(strcmp(source, "did:pkh:eip155:18446744073709551615:0xa11ce00000000000000000000000000000000001") == 0);

    /* Not a Tempo charge. */
    w = "Payment id=\"t\", realm=\"r\", method=\"stripe\", intent=\"charge\", request=\"e30\"";
    CHECK(trp_challenge_parse(w, strlen(w), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work), NULL) == TRP_ERR_UNSUPPORTED);
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
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, 1000, NULL) == TRP_ERR_BUFFER);
    CHECK(trp_tempo_charge(&ch, &opt, header, 100, work, sizeof(work), NULL) == TRP_ERR_BUFFER);
    /* One transfer fits in 4 KB of working space. */
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, 4096, NULL) == TRP_OK);

    key.fail = 1;
    CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work), NULL) == TRP_ERR_CRYPTO);
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
    CHECK(trp_parse_rfc3339("2023-02-29T00:00:00Z", 20, &t) == TRP_ERR_INVALID); /* not a leap year */
    CHECK(trp_parse_rfc3339("2026-04-31T00:00:00Z", 20, &t) == TRP_ERR_INVALID);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00", 19, &t) == TRP_ERR_INVALID);
    CHECK(trp_parse_rfc3339("2026-13-14T10:00:00Z", 20, &t) == TRP_ERR_INVALID);
    CHECK(trp_parse_rfc3339("2026-10-14T10:00:00Zjunk", 24, &t) == TRP_ERR_INVALID);
}

void test_charge(void)
{
    test_vectors();
    test_policy();
    test_errors();
    test_buffers();
    test_helpers();
}

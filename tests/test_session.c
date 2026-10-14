#include "test.h"

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/keccak.h"
#include "transponder/session.h"
#include "tempo_vectors.h"

/* Signs only digests ox signed, with ox's signatures (see SV_SIGNINGS). */
typedef struct {
    int calls;
    int unknown;
} table_key;

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    trp_hex_decode(hex, strlen(hex), out, cap, &n);
    return n;
}

static trp_err_t table_sign(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    table_key *k = (table_key *)ctx;
    size_t i;

    k->calls++;
    for (i = 0; i < sizeof(SV_SIGNINGS) / sizeof(SV_SIGNINGS[0]); i++) {
        uint8_t d[32];
        unhex(SV_SIGNINGS[i][0], d, 32);
        if (memcmp(d, digest, 32) == 0) {
            unhex(SV_SIGNINGS[i][1], r, 32);
            unhex(SV_SIGNINGS[i][2], s, 32);
            return TRP_OK;
        }
    }
    k->unknown++;
    return TRP_ERR_CRYPTO;
}

static char scratch[4096], header[8192];
static uint8_t work[8192];

typedef struct {
    trp_signer signer;
    table_key key;
    uint8_t owner[20];
    trp_spend_policy policy;
    trp_charge_options opt;
} fixture;

static void setup(fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->signer.sign_digest = table_sign;
    f->signer.ctx = &f->key;
    unhex(TV_PUBLIC_KEY, f->signer.public_key, 64);
    unhex(TV_OWNER, f->owner, 20);
    trp_u256_from_decimal("2000000", 7, f->policy.max_amount);
    f->opt.owner = f->owner;
    f->opt.signer = &f->signer;
    f->opt.policy = &f->policy;
    f->opt.now = SV_NOW;
    f->opt.valid_after = SV_VALID_AFTER;
    f->opt.gas_limit = SV_GAS;
    f->opt.max_fee_per_gas = SV_MAX_FEE;
}

static void u256(const char *dec, uint8_t out[32])
{
    trp_u256_from_decimal(dec, strlen(dec), out);
}

static int matches(const char *got, const char *want, const char *what)
{
    trp_test_checks++;
    if (strcmp(got, want) == 0) return 1;
    trp_test_failures++;
    printf("  FAIL session %s credential differs\n", what);
    return 0;
}

static void test_flow(void)
{
    fixture f;
    trp_challenge ch;
    trp_session s;
    uint8_t deposit[32], salt[32], amount[32], want[32];

    setup(&f);
    u256(SV_DEPOSIT, deposit);
    unhex(SV_SALT, salt, 32);
    CHECK(trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), &ch, scratch, sizeof(scratch)) == TRP_OK);

    /* The buffer sizes session.h documents: 4 KB out; 6.5 KB work for open and top-up, 4.5 KB otherwise. */
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, 4096, work, 6656) == TRP_OK);
    matches(header, SV_OPEN, "open");
    unhex(SV_CHANNEL_ID, want, 32);
    CHECK(memcmp(s.channel_id, want, 32) == 0);
    unhex(SV_EXPIRING_NONCE_HASH, want, 32);
    CHECK(memcmp(s.descriptor.expiring_nonce_hash, want, 32) == 0);
    u256("10", want); /* the open's voucher pays for its own request */
    CHECK(memcmp(s.cumulative, want, 32) == 0);

    u256(SV_VOUCHER, amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, 4096, work, 4608) == TRP_OK);
    matches(header, SV_VOUCHER_HEADER, "voucher");

    u256(SV_ADDITIONAL, amount);
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, 4096, work, 6656) == TRP_OK);
    matches(header, SV_TOP_UP, "topUp");
    u256("1500000", want);
    CHECK(memcmp(s.deposit, want, 32) == 0);

    CHECK(trp_session_close(&s, &ch, &f.signer, header, 4096, work, 4608) == TRP_OK);
    matches(header, SV_CLOSE, "close");
    CHECK(f.key.unknown == 0);
}

/* A session challenge with this request JSON. */
static trp_err_t parse_with(const char *request_json, trp_challenge *ch)
{
    static char wire[2048];
    char req[1024];

    if (trp_base64url_encode((const uint8_t *)request_json, strlen(request_json), req, sizeof(req)) != TRP_OK)
        return TRP_ERR_BUFFER;
    snprintf(wire, sizeof(wire),
             "Payment id=\"s\", realm=\"r\", method=\"tempo\", intent=\"session\", request=\"%s\"", req);
    return trp_challenge_parse(wire, strlen(wire), ch, scratch, sizeof(scratch));
}

#define SESSION_REQ(details)                                                                       \
    "{\"amount\":\"10\",\"currency\":\"0x20c0000000000000000000000000000000000000\","             \
    "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\",\"methodDetails\":{" details "}}"
#define ESCROW "\"escrowContract\":\"0x4d50500000000000000000000000000000000000\""

static void test_rules(void)
{
    fixture f;
    trp_challenge ch;
    trp_session s;
    trp_session_request r;
    uint8_t deposit[32], salt[32] = {1}, amount[32], digest[32], over[32];

    setup(&f);
    u256(SV_DEPOSIT, deposit);

    /* Request parsing. */
    CHECK(parse_with(SESSION_REQ(ESCROW ",\"sessionProtocol\":\"v2\""), &ch) == TRP_OK);
    CHECK(trp_session_request_parse(&ch, &r) == TRP_OK && r.chain_id == TRP_TEMPO_MAINNET);
    CHECK(parse_with(SESSION_REQ(ESCROW), &ch) == TRP_OK);
    CHECK(trp_session_request_parse(&ch, &r) == TRP_ERR_UNSUPPORTED); /* no sessionProtocol: v1 */
    CHECK(parse_with(SESSION_REQ(ESCROW ",\"sessionProtocol\":\"v1\""), &ch) == TRP_OK);
    CHECK(trp_session_request_parse(&ch, &r) == TRP_ERR_UNSUPPORTED);
    CHECK(parse_with(SESSION_REQ("\"sessionProtocol\":\"v2\""), &ch) == TRP_OK);
    CHECK(trp_session_request_parse(&ch, &r) == TRP_ERR_INVALID); /* no escrow */

    /* Another escrow contract is refused: the deposit goes only to the precompile. */
    CHECK(parse_with(SESSION_REQ("\"escrowContract\":\"0x1111111111111111111111111111111111111111\","
                                 "\"sessionProtocol\":\"v2\",\"chainId\":42431"), &ch) == TRP_OK);
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_UNSUPPORTED);

    /* The policy limits the deposit; a deposit below one unit's price is pointless. */
    CHECK(trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), &ch, scratch, sizeof(scratch)) == TRP_OK);
    u256("3000000", amount);
    CHECK(trp_session_open(&ch, &f.opt, amount, salt, &s, header, sizeof(header), work, sizeof(work)) == TRP_ERR_DENIED);
    u256("9", amount);
    CHECK(trp_session_open(&ch, &f.opt, amount, salt, &s, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);
    CHECK(f.key.calls == 0);

    /* Vouchers are cumulative: never down, never past the deposit. */
    unhex(SV_SALT, salt, 32);
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    u256("250", amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    u256("100", amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);
    u256("1000001", amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);

    /* A challenge for another payee cannot carry this channel's voucher. */
    CHECK(parse_with("{\"amount\":\"10\",\"currency\":\"0x20c0000000000000000000000000000000000000\","
                     "\"recipient\":\"0x9999999999999999999999999999999999999999\",\"methodDetails\":{" ESCROW
                     ",\"sessionProtocol\":\"v2\",\"chainId\":42431}}",
                     &ch) == TRP_OK);
    u256("300", amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);

    /* v2 amounts are uint96. */
    memset(over, 0, sizeof(over));
    over[19] = 1; /* 2^96 */
    CHECK(trp_voucher_digest(42431, TRP_CHANNEL_ESCROW, s.channel_id, over, digest) == TRP_ERR_INVALID);
    over[19] = 0;
    memset(over + 20, 0xff, 12); /* 2^96 - 1 */
    CHECK(trp_voucher_digest(42431, TRP_CHANNEL_ESCROW, s.channel_id, over, digest) == TRP_OK);
}

/* The selectors hard-coded in session.c, recomputed. */
static void test_selectors(void)
{
    const char *open = "open(address,address,address,uint96,bytes32,address)";
    const char *top_up = "topUp((address,address,address,address,bytes32,address,bytes32),uint96)";
    uint8_t h[32];

    trp_keccak256((const uint8_t *)open, strlen(open), h);
    CHECK_HEX(h, 4, "edc53b00");
    trp_keccak256((const uint8_t *)top_up, strlen(top_up), h);
    CHECK_HEX(h, 4, "dc48471e");
}

void test_session(void)
{
    test_flow();
    test_rules();
    test_selectors();
}

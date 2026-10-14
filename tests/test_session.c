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

static int is_zero(const uint8_t v[32])
{
    int i;
    for (i = 0; i < 32; i++)
        if (v[i]) return 0;
    return 1;
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
    /* Pending until the server accepts it. */
    u256(SV_DEPOSIT, want);
    CHECK(memcmp(s.deposit, want, 32) == 0);
    trp_session_top_up_confirmed(&s);
    u256("1500000", want);
    CHECK(memcmp(s.deposit, want, 32) == 0);
    CHECK(is_zero(s.pending_top_up));

    CHECK(trp_session_close(&s, &ch, &f.signer, header, 4096, work, 4608) == TRP_OK);
    matches(header, SV_CLOSE, "close");
    CHECK(s.closed == 1);
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

static trp_err_t count_and_allow(void *ctx, const trp_challenge *ch, const trp_charge_request *req)
{
    (void)ch;
    (void)req;
    ++*(int *)ctx;
    return TRP_OK;
}

static trp_err_t refuse(void *ctx, const trp_challenge *ch, const trp_charge_request *req)
{
    (void)ch;
    (void)req;
    ++*(int *)ctx;
    return TRP_ERR_DENIED;
}

/* What the state machine refuses: unconfirmed deposit, a second pending top-up, a closed channel, another key. */
static void test_state(void)
{
    fixture f;
    trp_challenge ch;
    trp_session s;
    trp_signer other;
    uint8_t deposit[32], salt[32], amount[32];
    int asked = 0;

    setup(&f);
    u256(SV_DEPOSIT, deposit);
    unhex(SV_SALT, salt, 32);
    CHECK(trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), &ch, scratch, sizeof(scratch)) == TRP_OK);

    /* approve sees the open deposit and can refuse it. */
    f.opt.approve = refuse;
    f.opt.approve_ctx = &asked;
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_DENIED);
    CHECK(asked == 1 && f.key.calls == 0);
    f.opt.approve = count_and_allow;
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    CHECK(asked == 2);

    /* A pending top-up does not count yet, and a second one waits for it. */
    u256(SV_ADDITIONAL, amount);
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    CHECK(asked == 3);
    u256("1000001", amount);
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_INVALID);
    u256("1", amount);
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);
    trp_session_top_up_failed(&s);
    u256(SV_DEPOSIT, amount);
    CHECK(memcmp(s.deposit, amount, 32) == 0 && is_zero(s.pending_top_up));

    /* The policy limits the channel's total: 1000000 + 1000001 is over 2000000. */
    u256("1000001", amount);
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_DENIED);
    u256("1000000", amount);
    f.opt.approve = NULL;
    /* Within the limit: the policy passes (the fake key then knows no ox digest for it). */
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_CRYPTO);
    CHECK(is_zero(s.pending_top_up));

    /* Only the channel's key signs its vouchers. */
    other = f.signer;
    other.public_key[0] ^= 1;
    u256("250", amount);
    CHECK(trp_session_voucher(&s, &ch, &other, amount, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_INVALID);
    CHECK(trp_session_close(&s, &ch, &other, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);

    /* After close (see test_flow): no vouchers or top-ups. */
    s.closed = 1;
    CHECK(trp_session_voucher(&s, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_INVALID);
    CHECK(trp_session_top_up(&s, &ch, &f.opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_ERR_INVALID);
}

/* minVoucherDelta: a raise below it is refused, the same amount again is fine. */
static void test_min_delta(void)
{
    fixture f;
    trp_challenge ch, ch2;
    trp_session s;
    trp_session_request r;
    uint8_t deposit[32], salt[32], amount[32];

    setup(&f);
    u256(SV_DEPOSIT, deposit);
    unhex(SV_SALT, salt, 32);
    CHECK(trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_session_open(&ch, &f.opt, deposit, salt, &s, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    CHECK(parse_with("{\"amount\":\"10\",\"currency\":\"0x20c0000000000000000000000000000000000000\","
                     "\"recipient\":\"0x742d35cc6634c0532925a3b844bc9e7595f8fe00\",\"methodDetails\":{" ESCROW
                     ",\"sessionProtocol\":\"v2\",\"chainId\":42431,\"minVoucherDelta\":\"500\"}}",
                     &ch2) == TRP_OK);
    CHECK(trp_session_request_parse(&ch2, &r) == TRP_OK && r.has_min_voucher_delta);
    u256("509", amount); /* open voucher is 10: a raise of 499 */
    CHECK(trp_session_voucher(&s, &ch2, &f.signer, amount, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_INVALID);
    u256("10", amount); /* the same amount: no raise */
    CHECK(trp_session_voucher(&s, &ch2, &f.signer, amount, header, sizeof(header), work, sizeof(work)) !=
          TRP_ERR_INVALID);
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

/* A JSON-RPC response carrying getChannelState's result. */
static const char *state_response(uint64_t settled, uint64_t deposit, uint32_t close_requested)
{
    static char buf[300];
    snprintf(buf, sizeof(buf),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x%064llx%064llx%064lx\"}", (unsigned long long)settled,
             (unsigned long long)deposit, (unsigned long)close_requested);
    return buf;
}

/* Change byte `at` of a saved session and seal it with a valid checksum again. */
static void tamper(const uint8_t *state, size_t at, uint8_t value, uint8_t out[TRP_SESSION_STATE_LEN])
{
    uint8_t sum[32];
    memcpy(out, state, TRP_SESSION_STATE_LEN);
    out[at] = value;
    trp_keccak256(out, TRP_SESSION_STATE_LEN - 4, sum);
    memcpy(out + TRP_SESSION_STATE_LEN - 4, sum, 4);
}

/* An open channel with a voucher of 250 and a pending top-up of 500000, as in test_flow. */
static void open_pending(fixture *f, trp_challenge *ch, trp_session *s)
{
    uint8_t deposit[32], salt[32], amount[32];

    setup(f);
    u256(SV_DEPOSIT, deposit);
    unhex(SV_SALT, salt, 32);
    CHECK(trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_session_open(ch, &f->opt, deposit, salt, s, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    CHECK(s->tx_valid_before == SV_NOW + 20); /* the challenge's expires caps valid_before */
    s->tx_valid_before = 0;                   /* so the top-up must set it again */
    u256(SV_VOUCHER, amount);
    CHECK(trp_session_voucher(s, ch, &f->signer, amount, header, sizeof(header), work, sizeof(work)) == TRP_OK);
    u256(SV_ADDITIONAL, amount);
    CHECK(trp_session_top_up(s, ch, &f->opt, amount, header, sizeof(header), work, sizeof(work)) == TRP_OK);
}

static void test_restart(void)
{
    fixture f;
    trp_challenge ch;
    trp_session s, back;
    uint8_t state[TRP_SESSION_STATE_LEN], again[TRP_SESSION_STATE_LEN], want[32], amount[32];
    char body[256], expected[256];
    const uint64_t expires = SV_NOW + 20; /* the challenge's expires caps valid_before */
    const uint64_t later = expires + TRP_SESSION_SYNC_MARGIN + 1;
    const char *r;

    open_pending(&f, &ch, &s);
    CHECK(s.tx_valid_before == expires);

    /* Save and load round-trip; anything else is refused. */
    trp_session_save(&s, state);
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    trp_session_save(&back, again);
    CHECK(memcmp(state, again, sizeof(state)) == 0);
    CHECK(memcmp(back.channel_id, s.channel_id, 32) == 0 && back.tx_valid_before == s.tx_valid_before);
    CHECK(trp_session_load(&back, state, sizeof(state) - 1) == TRP_ERR_INVALID);
    state[100] ^= 1;
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_ERR_INVALID);
    state[100] ^= 1;
    /* Well sealed but impossible: another version, a changed descriptor, a voucher past the deposit, closed = 2. */
    tamper(state, 4, 2, again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_ERR_INVALID);
    tamper(state, 100, (uint8_t)(state[100] ^ 1), again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_ERR_INVALID);
    tamper(state, 293 + 20, 0xff, again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_ERR_INVALID);
    tamper(state, 325, 2, again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_ERR_INVALID);
    tamper(state, 325, 1, again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_OK && back.closed == 1);

    /* The read the device sends, checked against viem's encoding. */
    snprintf(expected, sizeof(expected),
             "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":"
             "\"0x4d50500000000000000000000000000000000000\",\"data\":\"0x%s\"},\"latest\"]}",
             SV_STATE_CALLDATA);
    CHECK(trp_session_state_request(&back, body, sizeof(body)) == TRP_OK);
    CHECK(strcmp(body, expected) == 0);
    CHECK(trp_session_state_request(&back, body, strlen(expected)) == TRP_ERR_BUFFER);

    /* The top-up landed: the chain shows it (viem-encoded result: settled 200, deposit 1500000). */
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x%s\"}", SV_STATE_RESULT);
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    CHECK(trp_session_sync(&back, body, strlen(body), SV_NOW) == TRP_OK);
    u256("1500000", want);
    CHECK(memcmp(back.deposit, want, 32) == 0 && is_zero(back.pending_top_up));
    u256(SV_VOUCHER, want);
    CHECK(memcmp(back.cumulative, want, 32) == 0 && back.closed == 0);
    /* And the restored session signs the same voucher again, byte for byte. */
    u256(SV_VOUCHER, amount);
    CHECK(trp_session_voucher(&back, &ch, &f.signer, amount, header, 4096, work, 4608) == TRP_OK);
    matches(header, SV_VOUCHER_HEADER, "restored voucher");

    /* The top-up is not on chain: pending while it could land, failed after. */
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    r = state_response(200, 1000000, 0);
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_ERR_PENDING);
    CHECK(trp_session_sync(&back, r, strlen(r), expires + 1) == TRP_ERR_PENDING); /* RPC nodes may lag */
    trp_session_save(&back, again);
    CHECK(memcmp(state, again, sizeof(state)) == 0); /* unchanged */
    CHECK(trp_session_sync(&back, r, strlen(r), later) == TRP_OK);
    u256(SV_DEPOSIT, want);
    CHECK(memcmp(back.deposit, want, 32) == 0 && is_zero(back.pending_top_up) && back.closed == 0);

    /* The server settled past the saved voucher: the cumulative follows. */
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    r = state_response(300, 1500000, 0);
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_OK);
    u256("300", want);
    CHECK(memcmp(back.cumulative, want, 32) == 0);

    /* No deposit: the open may still land; after that the channel is gone. */
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    r = state_response(0, 0, 0);
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_ERR_PENDING);
    CHECK(trp_session_sync(&back, r, strlen(r), later) == TRP_OK);
    CHECK(back.closed == 1 && is_zero(back.pending_top_up));
    trp_session_save(&back, again);
    CHECK(trp_session_load(&back, again, sizeof(again)) == TRP_OK && back.closed == 1);
    u256("300", amount);
    CHECK(trp_session_voucher(&back, &ch, &f.signer, amount, header, sizeof(header), work, sizeof(work)) ==
          TRP_ERR_INVALID);

    /* A close request on chain ends the channel for the device too. */
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    r = state_response(200, 1500000, 1791975000u);
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_OK);
    CHECK(back.closed == 1);

    /* Errors and malformed results change nothing. */
    CHECK(trp_session_load(&back, state, sizeof(state)) == TRP_OK);
    r = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"x\"}}";
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_ERR_INVALID);
    r = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x\"}";
    CHECK(trp_session_sync(&back, r, strlen(r), SV_NOW) == TRP_ERR_INVALID);
    snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x01%s\"}", &SV_STATE_RESULT[2]);
    CHECK(trp_session_sync(&back, body, strlen(body), SV_NOW) == TRP_ERR_INVALID); /* settled over 96 bits */
    trp_session_save(&back, again);
    CHECK(memcmp(state, again, sizeof(state)) == 0);
}

void test_session(void)
{
    test_restart();
    test_flow();
    test_rules();
    test_state();
    test_min_delta();
    test_selectors();
}

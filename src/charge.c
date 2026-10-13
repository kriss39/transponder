#include "transponder/charge.h"

#include <string.h>

#include "transponder/credential.h"
#include "transponder/hex.h"
#include "transponder/json.h"
#include "transponder/keccak.h"

#define DEFAULT_MAX_STRING 80 /* longest request string read here: a 0x-prefixed bytes32 */

/* ---- small helpers ----------------------------------------------------- */

static int str_eq(trp_str s, const char *lit)
{
    return s.ptr != NULL && s.len == strlen(lit) && memcmp(s.ptr, lit, s.len) == 0;
}

static int digits(const char *s, int n, int *out)
{
    int i, v = 0;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return 1;
}

/* Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

trp_err_t trp_parse_rfc3339(const char *s, size_t len, uint64_t *out)
{
    int year, month, day, hour, minute, second, off_h = 0, off_m = 0;
    int64_t t;
    size_t i = 19;

    if (len < 20) return TRP_ERR_INVALID;
    if (!digits(s, 4, &year) || s[4] != '-' || !digits(s + 5, 2, &month) || s[7] != '-' ||
        !digits(s + 8, 2, &day) || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') ||
        !digits(s + 11, 2, &hour) || s[13] != ':' || !digits(s + 14, 2, &minute) || s[16] != ':' ||
        !digits(s + 17, 2, &second))
        return TRP_ERR_INVALID;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60)
        return TRP_ERR_INVALID;

    if (i < len && s[i] == '.') { /* fractional seconds are dropped */
        i++;
        if (i >= len || s[i] < '0' || s[i] > '9') return TRP_ERR_INVALID;
        while (i < len && s[i] >= '0' && s[i] <= '9') i++;
    }
    if (i < len && (s[i] == 'Z' || s[i] == 'z')) {
        i++;
    } else if (i + 6 == len && (s[i] == '+' || s[i] == '-')) {
        if (!digits(s + i + 1, 2, &off_h) || s[i + 3] != ':' || !digits(s + i + 4, 2, &off_m) ||
            off_h > 23 || off_m > 59)
            return TRP_ERR_INVALID;
        if (s[i] == '-') {
            off_h = -off_h;
            off_m = -off_m;
        }
        i += 6;
    } else {
        return TRP_ERR_INVALID;
    }
    if (i != len) return TRP_ERR_INVALID;

    t = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second -
        (off_h * 3600 + off_m * 60);
    if (t < 0) return TRP_ERR_INVALID;
    *out = (uint64_t)t;
    return TRP_OK;
}

void trp_address_checksum(const uint8_t address[TRP_ADDRESS_LEN], char out[43])
{
    char lower[41];
    uint8_t h[32];
    int i;

    trp_hex_encode(address, TRP_ADDRESS_LEN, 0, lower, sizeof(lower));
    trp_keccak256((const uint8_t *)lower, 40, h);
    out[0] = '0';
    out[1] = 'x';
    for (i = 0; i < 40; i++) {
        char c = lower[i];
        int nib = (i % 2 == 0) ? (h[i / 2] >> 4) : (h[i / 2] & 0x0f);
        out[2 + i] = (c >= 'a' && c <= 'f' && nib >= 8) ? (char)(c - 'a' + 'A') : c;
    }
    out[42] = '\0';
}

/* Unsigned decimal, NUL-terminated; returns the length. */
static size_t u64_to_dec(uint64_t v, char out[21])
{
    char tmp[20];
    size_t n = 0, i;

    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    for (i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = '\0';
    return n;
}

/* A string field of `obj`, unescaped into `buf`. */
static trp_err_t get_string(const trp_json *obj, const char *key, char *buf, size_t cap, size_t *len)
{
    trp_json v;
    trp_err_t err = trp_json_get(obj, key, &v);
    if (err != TRP_OK) return err;
    if (v.type != TRP_JSON_STRING) return TRP_ERR_INVALID;
    return trp_json_get_string(&v, buf, cap, len);
}

/* A field holding exactly `n` bytes as 0x-prefixed hex. */
static trp_err_t get_hex_bytes(const trp_json *obj, const char *key, uint8_t *out, size_t n)
{
    char buf[DEFAULT_MAX_STRING];
    size_t len, got;
    trp_err_t err = get_string(obj, key, buf, sizeof(buf), &len);

    if (err == TRP_ERR_BUFFER) return TRP_ERR_INVALID;
    if (err != TRP_OK) return err;
    if (len != 2 + 2 * n || buf[0] != '0' || (buf[1] != 'x' && buf[1] != 'X')) return TRP_ERR_INVALID;
    if (trp_hex_decode(buf, len, out, n, &got) != TRP_OK || got != n) return TRP_ERR_INVALID;
    return TRP_OK;
}

/* Carves fixed-size pieces off the caller's work buffer. */
typedef struct {
    uint8_t *p;
    size_t left;
} carver;

static void *take(carver *c, size_t n)
{
    void *p;
    if (c->left < n) return NULL;
    p = c->p;
    c->p += n;
    c->left -= n;
    return p;
}

/* ---- the charge -------------------------------------------------------- */

typedef struct {
    uint8_t amount[TRP_U256_LEN];
    uint8_t currency[TRP_ADDRESS_LEN];
    uint8_t recipient[TRP_ADDRESS_LEN];
    uint8_t memo[TRP_MEMO_LEN];
    int has_memo;
    int fee_payer;
    uint64_t chain_id;
} charge_request;

static int is_zero(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

static trp_err_t read_request(const trp_challenge *ch, uint64_t default_chain_id, charge_request *r)
{
    const trp_json *req = &ch->request_json;
    trp_json details, v, item;
    char buf[DEFAULT_MAX_STRING];
    size_t len, pos = 0;
    int pull = 0;
    trp_err_t err;

    memset(r, 0, sizeof(*r));
    r->chain_id = default_chain_id;

    err = get_string(req, "amount", buf, sizeof(buf), &len);
    if (err == TRP_ERR_BUFFER) return TRP_ERR_INVALID;
    if (err != TRP_OK) return TRP_ERR_INVALID;
    if ((err = trp_u256_from_decimal(buf, len, r->amount)) != TRP_OK) return err;
    if (is_zero(r->amount, sizeof(r->amount))) return TRP_ERR_UNSUPPORTED; /* proof credential */
    if (get_hex_bytes(req, "currency", r->currency, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    if (get_hex_bytes(req, "recipient", r->recipient, TRP_ADDRESS_LEN) != TRP_OK)
        return TRP_ERR_INVALID;

    err = trp_json_get(req, "methodDetails", &details);
    if (err == TRP_ERR_NOT_FOUND) return r->chain_id ? TRP_OK : TRP_ERR_INVALID;
    if (err != TRP_OK || details.type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;

    err = trp_json_get(&details, "chainId", &v);
    if (err == TRP_OK) {
        if (trp_json_get_uint64(&v, &r->chain_id) != TRP_OK) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }
    if (r->chain_id == 0) return TRP_ERR_INVALID;

    err = trp_json_get(&details, "feePayer", &v);
    if (err == TRP_OK) {
        if (trp_json_get_bool(&v, &r->fee_payer) != TRP_OK) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }

    err = get_hex_bytes(&details, "memo", r->memo, TRP_MEMO_LEN);
    if (err == TRP_OK) r->has_memo = 1;
    else if (err != TRP_ERR_NOT_FOUND) return TRP_ERR_INVALID;

    err = trp_json_get(&details, "supportedModes", &v);
    if (err == TRP_OK) {
        if (v.type != TRP_JSON_ARRAY) return TRP_ERR_INVALID;
        while ((err = trp_json_next(&v, &pos, &item)) == TRP_OK) {
            if (item.type == TRP_JSON_STRING && item.len == 6 && memcmp(item.ptr, "\"pull\"", 6) == 0)
                pull = 1;
        }
        if (err != TRP_ERR_NOT_FOUND) return err;
        if (!pull) return TRP_ERR_UNSUPPORTED; /* push only */
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }

    err = trp_json_get(&details, "splits", &v);
    if (err == TRP_OK) {
        pos = 0;
        if (v.type != TRP_JSON_ARRAY) return TRP_ERR_INVALID;
        if (trp_json_next(&v, &pos, &item) == TRP_OK) return TRP_ERR_UNSUPPORTED;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }
    return TRP_OK;
}

trp_err_t trp_tempo_charge(const trp_challenge *ch, const trp_charge_options *opt, char *out,
                           size_t out_cap, uint8_t *work, size_t work_cap)
{
    enum { RLP_CAP = 512, ENVELOPE_CAP = 512, KEYCHAIN_CAP = 1 + TRP_ADDRESS_LEN + TRP_P256_SIGNATURE_LEN };
    charge_request req;
    carver c;
    uint8_t *calldata, *rlp_buf, *keychain, *envelope;
    uint8_t sender_hash[32], digest[32], r[32], s[32], p256[TRP_P256_SIGNATURE_LEN];
    char *payload_buf, *json_scratch;
    char source[64], address[43], chain[21];
    size_t keychain_len, envelope_len, payload_cap, json_cap, n;
    uint64_t valid_before;
    trp_tempo_call call;
    trp_tempo_tx tx;
    trp_json_writer w;
    trp_err_t err;

    if (!ch || !opt || !opt->owner || !opt->signer || !opt->signer->sign_digest || opt->now == 0 ||
        opt->gas_limit == 0)
        return TRP_ERR_INVALID;
    if (!str_eq(ch->method, "tempo") || !str_eq(ch->intent, "charge")) return TRP_ERR_UNSUPPORTED;
    if ((err = read_request(ch, opt->default_chain_id, &req)) != TRP_OK) return err;

    /* Expire within TRP_CHARGE_MAX_VALIDITY seconds, and never after the challenge does. */
    valid_before = opt->now + TRP_CHARGE_MAX_VALIDITY;
    if (ch->expires.ptr) {
        uint64_t expires;
        if (trp_parse_rfc3339(ch->expires.ptr, ch->expires.len, &expires) != TRP_OK)
            return TRP_ERR_INVALID;
        if (expires <= opt->now) return TRP_ERR_INVALID; /* already expired */
        if (expires < valid_before) valid_before = expires;
    }
    if (!req.has_memo) trp_mpp_attribution_memo(ch->realm, opt->client_id, ch->id, req.memo);

    c.p = work;
    c.left = work_cap;
    calldata = (uint8_t *)take(&c, TRP_TRANSFER_WITH_MEMO_LEN);
    rlp_buf = (uint8_t *)take(&c, RLP_CAP);
    keychain = (uint8_t *)take(&c, KEYCHAIN_CAP);
    envelope = (uint8_t *)take(&c, ENVELOPE_CAP);
    payload_cap = sizeof("{\"signature\":\"0x\",\"type\":\"transaction\"}") + 2 * ENVELOPE_CAP;
    payload_buf = (char *)take(&c, payload_cap);
    if (!calldata || !rlp_buf || !keychain || !envelope || !payload_buf) return TRP_ERR_BUFFER;
    json_scratch = (char *)c.p;
    json_cap = c.left;

    trp_tempo_transfer_with_memo(req.recipient, req.amount, req.memo, calldata);
    call.to = req.currency;
    call.data = calldata;
    call.data_len = TRP_TRANSFER_WITH_MEMO_LEN;

    memset(&tx, 0, sizeof(tx));
    tx.chain_id = req.chain_id;
    tx.max_priority_fee_per_gas = opt->max_priority_fee_per_gas;
    tx.max_fee_per_gas = opt->max_fee_per_gas;
    tx.gas_limit = opt->gas_limit;
    tx.calls = &call;
    tx.call_count = 1;
    tx.valid_before = valid_before;
    tx.valid_after = opt->valid_after;
    tx.fee_payer = req.fee_payer;
    tx.fee_token = req.fee_payer ? NULL : opt->fee_token;

    if ((err = trp_tempo_sender_hash(&tx, rlp_buf, RLP_CAP, sender_hash)) != TRP_OK) return err;
    trp_tempo_keychain_digest(sender_hash, opt->owner, digest);
    if (opt->signer->sign_digest(opt->signer->ctx, digest, r, s) != TRP_OK) return TRP_ERR_CRYPTO;
    if ((err = trp_p256_signature(r, s, opt->signer->public_key, opt->signer->pre_hash, p256)) != TRP_OK) return TRP_ERR_CRYPTO;
    if ((err = trp_keychain_signature(opt->owner, p256, sizeof(p256), keychain, KEYCHAIN_CAP,
                                      &keychain_len)) != TRP_OK)
        return err;
    if ((err = trp_tempo_serialize(&tx, keychain, keychain_len, envelope, ENVELOPE_CAP,
                                   &envelope_len)) != TRP_OK)
        return err;

    /* {"signature":"0x76…","type":"transaction"}, keys in mppx's order. */
    trp_jw_init(&w, payload_buf, payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "signature");
    trp_jw_raw(&w, "\"", 1);
    if (w.err == TRP_OK) {
        if (trp_hex_encode(envelope, envelope_len, 1, payload_buf + w.len, payload_cap - w.len) != TRP_OK)
            return TRP_ERR_BUFFER;
        w.len += 2 + 2 * envelope_len;
    }
    trp_jw_raw(&w, "\"", 1);
    trp_jw_key(&w, "type");
    trp_jw_string(&w, "transaction", 11);
    trp_jw_object_end(&w);
    if ((err = trp_jw_finish(&w)) != TRP_OK) return err;

    /* did:pkh:eip155:<chainId>:<owner> */
    trp_address_checksum(opt->owner, address);
    n = u64_to_dec(req.chain_id, chain);
    memcpy(source, "did:pkh:eip155:", 15);
    memcpy(source + 15, chain, n);
    source[15 + n] = ':';
    memcpy(source + 16 + n, address, 43);

    return trp_credential_encode(ch, payload_buf, w.len, source, out, out_cap, json_scratch, json_cap);
}

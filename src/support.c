/* Helpers shared by the charge and session flows. */

#include <string.h>

#include "transponder/charge.h"
#include "transponder/hex.h"
#include "transponder/json.h"
#include "transponder/keccak.h"
#include "internal.h"

int trp__str_eq(trp_str s, const char *lit)
{
    return s.ptr != NULL && s.len == strlen(lit) && memcmp(s.ptr, lit, s.len) == 0;
}

int trp__is_zero(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i]) return 0;
    return 1;
}

size_t trp__u64_to_dec(uint64_t v, char out[21])
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

void *trp__take(trp__carver *c, size_t n)
{
    void *p;
    if (c->left < n) return NULL;
    p = c->p;
    c->p += n;
    c->left -= n;
    return p;
}

/* ---- request fields ---------------------------------------------------- */

trp_err_t trp__json_string(const trp_json *obj, const char *key, char *buf, size_t cap, size_t *len)
{
    trp_json v;
    trp_err_t err = trp_json_get(obj, key, &v);

    if (err != TRP_OK) return err;
    if (v.type != TRP_JSON_STRING) return TRP_ERR_INVALID;
    err = trp_json_get_string(&v, buf, cap, len);
    return err == TRP_ERR_BUFFER ? TRP_ERR_INVALID : err;
}

trp_err_t trp__json_hex(const trp_json *obj, const char *key, uint8_t *out, size_t n)
{
    char buf[TRP__MAX_FIELD];
    size_t len, got;
    trp_err_t err = trp__json_string(obj, key, buf, sizeof(buf), &len);

    if (err != TRP_OK) return err;
    if (len != 2 + 2 * n || buf[0] != '0' || (buf[1] != 'x' && buf[1] != 'X')) return TRP_ERR_INVALID;
    if (trp_hex_decode(buf, len, out, n, &got) != TRP_OK || got != n) return TRP_ERR_INVALID;
    return TRP_OK;
}

trp_err_t trp__json_u256(const trp_json *obj, const char *key, uint8_t out[32])
{
    char buf[TRP__MAX_FIELD];
    size_t len;
    trp_err_t err = trp__json_string(obj, key, buf, sizeof(buf), &len);

    if (err != TRP_OK) return err;
    return trp_u256_from_decimal(buf, len, out) == TRP_OK ? TRP_OK : TRP_ERR_INVALID;
}

/* ---- time -------------------------------------------------------------- */

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
        !digits(s + 8, 2, &day) || s[10] != 'T' ||
        !digits(s + 11, 2, &hour) || s[13] != ':' || !digits(s + 14, 2, &minute) || s[16] != ':' ||
        !digits(s + 17, 2, &second))
        return TRP_ERR_INVALID;
    if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 60)
        return TRP_ERR_INVALID;
    {
        static const int DAYS[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        int leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        if (day > DAYS[month - 1] + (month == 2 && leap)) return TRP_ERR_INVALID;
    }

    if (i < len && s[i] == '.') { /* fractional seconds are dropped */
        i++;
        if (i >= len || s[i] < '0' || s[i] > '9') return TRP_ERR_INVALID;
        while (i < len && s[i] >= '0' && s[i] <= '9') i++;
    }
    if (i < len && s[i] == 'Z') {
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

trp_err_t trp__valid_before(const trp_challenge *ch, uint64_t now, uint64_t *out)
{
    *out = now + TRP_CHARGE_MAX_VALIDITY;
    if (ch->expires.ptr) {
        uint64_t expires;
        if (trp_parse_rfc3339(ch->expires.ptr, ch->expires.len, &expires) != TRP_OK) return TRP_ERR_INVALID;
        if (expires <= now) return TRP_ERR_INVALID; /* already expired */
        if (expires < *out) *out = expires;
    }
    return TRP_OK;
}

/* ---- addresses and signing ---------------------------------------------- */

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

size_t trp__did_pkh(uint64_t chain_id, const uint8_t owner[TRP_ADDRESS_LEN], char out[TRP__DID_MAX])
{
    char address[43], chain[21];
    size_t n = trp__u64_to_dec(chain_id, chain);

    trp_address_checksum(owner, address);
    memcpy(out, "did:pkh:eip155:", 15);
    memcpy(out + 15, chain, n);
    out[15 + n] = ':';
    memcpy(out + 16 + n, address, 43);
    return 16 + n + 42;
}

trp_err_t trp__sign_p256(const trp_signer *signer, const uint8_t digest[32],
                         uint8_t out[TRP_P256_SIGNATURE_LEN])
{
    uint8_t r[32], s[32];

    if (signer->sign_digest(signer->ctx, digest, r, s) != TRP_OK) return TRP_ERR_CRYPTO;
    if (trp_p256_signature(r, s, signer->public_key, signer->pre_hash, out) != TRP_OK) return TRP_ERR_CRYPTO;
    return TRP_OK;
}

trp_err_t trp__keychain_sign_tx(const trp_tempo_tx *tx, const uint8_t owner[TRP_ADDRESS_LEN],
                                const trp_signer *signer, uint8_t *rlp_buf, size_t rlp_cap,
                                uint8_t *envelope, size_t envelope_cap, size_t *envelope_len)
{
    uint8_t sender_hash[32], digest[32], p256[TRP_P256_SIGNATURE_LEN];
    uint8_t keychain[1 + TRP_ADDRESS_LEN + TRP_P256_SIGNATURE_LEN];
    size_t keychain_len;
    trp_err_t err;

    if ((err = trp_tempo_sender_hash(tx, rlp_buf, rlp_cap, sender_hash)) != TRP_OK) return err;
    trp_tempo_keychain_digest(sender_hash, owner, digest);
    if ((err = trp__sign_p256(signer, digest, p256)) != TRP_OK) return err;
    if ((err = trp_keychain_signature(owner, p256, sizeof(p256), keychain, sizeof(keychain),
                                      &keychain_len)) != TRP_OK)
        return err;
    return trp_tempo_serialize(tx, keychain, keychain_len, envelope, envelope_cap, envelope_len);
}

/* ---- JSON output --------------------------------------------------------- */

void trp__jw_hex(trp_json_writer *w, const uint8_t *bytes, size_t len)
{
    trp_jw_raw(w, "\"", 1);
    if (w->err != TRP_OK) return;
    /* 0x + two digits per byte, plus the closing quote and the writer's NUL slot */
    if (w->cap - w->len < 2 + 2 * len + 2) {
        w->err = TRP_ERR_BUFFER;
        return;
    }
    trp_hex_encode(bytes, len, 1, w->buf + w->len, w->cap - w->len);
    w->len += 2 + 2 * len;
    trp_jw_raw(w, "\"", 1);
}

void trp__jw_address(trp_json_writer *w, const uint8_t address[TRP_ADDRESS_LEN])
{
    char text[43];
    trp_address_checksum(address, text);
    trp_jw_string(w, text, 42);
}

void trp__jw_decimal(trp_json_writer *w, const uint8_t value[32])
{
    char text[80];
    uint8_t v[32];
    size_t n = 0, i;
    int nonzero;

    memcpy(v, value, 32);
    do { /* repeated division by 10 */
        unsigned rem = 0;
        nonzero = 0;
        for (i = 0; i < 32; i++) {
            unsigned cur = (rem << 8) | v[i];
            v[i] = (uint8_t)(cur / 10);
            rem = cur % 10;
            if (v[i]) nonzero = 1;
        }
        text[n++] = (char)('0' + rem);
    } while (nonzero);
    for (i = 0; i < n / 2; i++) {
        char t = text[i];
        text[i] = text[n - 1 - i];
        text[n - 1 - i] = t;
    }
    trp_jw_string(w, text, n);
}

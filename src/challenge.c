#include "transponder/challenge.h"

#include <string.h>

#include "transponder/base64url.h"
#include "internal.h"

#define MAX_PARAMS 32
#define SCHEME "payment"
#define SCHEME_LEN 7

/* Values are copied into the caller's scratch buffer, one after another. */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
} arena;

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static int is_key_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '-';
}

static char to_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive comparison of `s` (length `len`) with the NUL-terminated `lit`. */
static int ieq(const char *s, size_t len, const char *lit)
{
    size_t i;

    for (i = 0; i < len; i++)
        if (lit[i] == '\0' || to_lower(s[i]) != to_lower(lit[i])) return 0;
    return lit[len] == '\0';
}

static int ieq_str(const char *a, size_t alen, const char *b, size_t blen)
{
    size_t i;

    if (alen != blen) return 0;
    for (i = 0; i < alen; i++)
        if (to_lower(a[i]) != to_lower(b[i])) return 0;
    return 1;
}

static int str_eq(trp_str s, const char *lit)
{
    return s.ptr != NULL && s.len == strlen(lit) && memcmp(s.ptr, lit, s.len) == 0;
}

static int hex4(const char *p, uint32_t *out)
{
    uint32_t v = 0;
    int i;

    for (i = 0; i < 4; i++) {
        int n = trp__hex_nibble(p[i]);
        if (n < 0) return 0;
        v = (v << 4) | (uint32_t)n;
    }
    *out = v;
    return 1;
}

/*
 * Position of the next "Payment" scheme at or after `from`: outside quoted
 * strings, at the start of the value or after a comma, and followed by
 * whitespace or the end. Returns `len` when there is none.
 */
static size_t find_scheme(const char *v, size_t len, size_t from)
{
    int in_quotes = 0, escaped = 0;
    size_t i;

    for (i = from; i < len; i++) {
        size_t b;

        if (in_quotes) {
            if (escaped) escaped = 0;
            else if (v[i] == '\\') escaped = 1;
            else if (v[i] == '"') in_quotes = 0;
            continue;
        }
        if (v[i] == '"') {
            in_quotes = 1;
            continue;
        }
        if (len - i < SCHEME_LEN || !ieq(v + i, SCHEME_LEN, SCHEME)) continue;
        if (i + SCHEME_LEN < len && !is_space(v[i + SCHEME_LEN])) continue;
        b = i;
        while (b > 0 && is_space(v[b - 1])) b--;
        if (b > 0 && v[b - 1] != ',') continue;
        return i;
    }
    return len;
}

static trp_err_t append(arena *a, const char *s, size_t n)
{
    if (a->cap - a->len < n + 1) return TRP_ERR_BUFFER;
    memcpy(a->buf + a->len, s, n);
    a->len += n;
    return TRP_OK;
}

/* NUL-terminate the bytes appended since `mark` and describe them. */
static trp_err_t seal(arena *a, size_t mark, trp_str *out)
{
    if (a->cap - a->len < 1) return TRP_ERR_BUFFER;
    a->buf[a->len++] = '\0';
    out->ptr = a->buf + mark;
    out->len = a->len - mark - 1;
    return TRP_OK;
}

/*
 * A quoted-string starting after its opening quote. Escapes follow mppx:
 * a backslash keeps the next character, except that \uXXXX decodes a
 * UTF-16 code unit (surrogate pairs combine; a lone surrogate is invalid).
 */
static trp_err_t read_quoted(const char *v, size_t len, size_t *pos, arena *a, trp_str *out)
{
    size_t i = *pos, mark = a->len;
    trp_err_t err;

    while (i < len) {
        char c = v[i++];
        if (c == '"') {
            *pos = i;
            return seal(a, mark, out);
        }
        if (c != '\\') {
            if ((err = append(a, &c, 1)) != TRP_OK) return err;
            continue;
        }
        if (i >= len) break;
        c = v[i++];
        if (c == 'u' && len - i >= 4) {
            uint32_t cp, lo;
            char utf8[4];
            size_t n;
            if (hex4(v + i, &cp)) {
                i += 4;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (len - i < 6 || v[i] != '\\' || v[i + 1] != 'u' || !hex4(v + i + 2, &lo) ||
                        lo < 0xdc00 || lo > 0xdfff)
                        return TRP_ERR_INVALID;
                    i += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                n = trp__utf8_put(cp, utf8);
                if (n == 0) return TRP_ERR_INVALID;
                if ((err = append(a, utf8, n)) != TRP_OK) return err;
                continue;
            }
        }
        if ((err = append(a, &c, 1)) != TRP_OK) return err;
    }
    return TRP_ERR_INVALID; /* unterminated */
}

static trp_err_t read_token(const char *v, size_t len, size_t *pos, arena *a, trp_str *out)
{
    size_t start = *pos, end, mark = a->len;
    trp_err_t err;

    end = start;
    while (end < len && v[end] != ',') end++;
    *pos = end;
    while (end > start && is_space(v[end - 1])) end--;
    while (start < end && is_space(v[start])) start++;
    if ((err = append(a, v + start, end - start)) != TRP_OK) return err;
    return seal(a, mark, out);
}

static trp_str *field_for(trp_challenge *ch, const char *key, size_t len)
{
    if (ieq(key, len, "id")) return &ch->id;
    if (ieq(key, len, "realm")) return &ch->realm;
    if (ieq(key, len, "method")) return &ch->method;
    if (ieq(key, len, "intent")) return &ch->intent;
    if (ieq(key, len, "request")) return &ch->request;
    if (ieq(key, len, "description")) return &ch->description;
    if (ieq(key, len, "digest")) return &ch->digest;
    if (ieq(key, len, "expires")) return &ch->expires;
    if (ieq(key, len, "header")) return &ch->header;
    if (ieq(key, len, "opaque")) return &ch->opaque;
    return NULL;
}

static int valid_method(trp_str m)
{
    size_t i;

    if (m.len == 0 || m.ptr[0] < 'a' || m.ptr[0] > 'z') return 0;
    for (i = 1; i < m.len; i++) {
        char c = m.ptr[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* Parse the auth-params that follow a Payment scheme token at `start`. */
static trp_err_t parse_at(const char *v, size_t len, size_t start, trp_challenge *out, arena *a)
{
    trp_str seen[MAX_PARAMS];
    size_t nseen = 0, i = start + SCHEME_LEN, k, decoded_cap, decoded_len;
    trp_err_t err;
    uint8_t *decoded;

    memset(out, 0, sizeof(*out));

    while (i < len) {
        size_t key_start, key_len;
        trp_str value, *field;
        size_t mark = a->len;

        while (i < len && (is_space(v[i]) || v[i] == ',')) i++;
        if (i >= len) break;
        key_start = i;
        while (i < len && is_key_char(v[i])) i++;
        key_len = i - key_start;
        if (key_len == 0) return TRP_ERR_INVALID;
        while (i < len && is_space(v[i])) i++;
        if (i >= len || v[i] != '=') break; /* the next auth scheme begins here */
        i++;
        while (i < len && is_space(v[i])) i++;

        for (k = 0; k < nseen; k++)
            if (ieq_str(seen[k].ptr, seen[k].len, v + key_start, key_len)) return TRP_ERR_INVALID;
        if (nseen == MAX_PARAMS) return TRP_ERR_UNSUPPORTED;
        seen[nseen].ptr = v + key_start;
        seen[nseen].len = key_len;
        nseen++;

        if (i < len && v[i] == '"') {
            i++;
            err = read_quoted(v, len, &i, a, &value);
        } else {
            err = read_token(v, len, &i, a, &value);
        }
        if (err != TRP_OK) return err;

        field = field_for(out, v + key_start, key_len);
        if (field) *field = value;
        else a->len = mark; /* unknown parameter: drop its value */
    }

    if (!out->id.ptr || out->id.len == 0 || !out->realm.ptr || !out->method.ptr ||
        !out->intent.ptr || !out->request.ptr)
        return TRP_ERR_INVALID;
    if (!valid_method(out->method)) return TRP_ERR_INVALID;
    if (out->request.len > TRP_CHALLENGE_MAX_REQUEST) return TRP_ERR_INVALID;

    if (out->header.ptr) {
        if (ieq(out->header.ptr, out->header.len, "authorization")) {
            out->header.ptr = NULL; /* the default field */
            out->header.len = 0;
        } else if (!ieq(out->header.ptr, out->header.len, "payment-authorization")) {
            return TRP_ERR_UNSUPPORTED;
        }
    }

    decoded = (uint8_t *)(a->buf + a->len);
    decoded_cap = a->cap - a->len;
    if ((err = trp_base64url_decode(out->request.ptr, out->request.len, decoded, decoded_cap,
                                    &decoded_len)) != TRP_OK)
        return err;
    a->len += decoded_len;
    if (!trp_utf8_valid(decoded, decoded_len)) return TRP_ERR_INVALID;
    if ((err = trp_json_parse((const char *)decoded, decoded_len, &out->request_json)) != TRP_OK)
        return err;
    if (out->request_json.type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;
    return TRP_OK;
}

trp_err_t trp_challenge_parse(const char *value, size_t len, trp_challenge *out,
                              char *scratch, size_t scratch_cap)
{
    arena a;
    size_t start = find_scheme(value, len, 0);

    if (start == len) return TRP_ERR_INVALID;
    a.buf = scratch;
    a.cap = scratch_cap;
    a.len = 0;
    return parse_at(value, len, start, out, &a);
}

trp_err_t trp_challenge_select(const char *value, size_t len, const char *method,
                               const char *intent, trp_challenge *out, char *scratch,
                               size_t scratch_cap)
{
    size_t start = find_scheme(value, len, 0);

    while (start < len) {
        arena a;
        a.buf = scratch;
        a.cap = scratch_cap;
        a.len = 0;
        if (parse_at(value, len, start, out, &a) == TRP_OK &&
            (method == NULL || str_eq(out->method, method)) &&
            (intent == NULL || str_eq(out->intent, intent)))
            return TRP_OK;
        start = find_scheme(value, len, start + 1);
    }
    memset(out, 0, sizeof(*out));
    return TRP_ERR_NOT_FOUND;
}

const char *trp_challenge_credential_header(const trp_challenge *challenge)
{
    return challenge->header.ptr ? "Payment-Authorization" : "Authorization";
}

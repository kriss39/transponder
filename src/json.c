#include "transponder/json.h"

#include <string.h>

#include "internal.h"

/* ---- UTF-8 ------------------------------------------------------------ */

/* Length of the well-formed UTF-8 sequence at `s`, or 0 if it is malformed. */
static size_t utf8_seq(const uint8_t *s, size_t avail)
{
    uint8_t b = s[0];

    if (b < 0x80) return 1;
    if (b >= 0xc2 && b <= 0xdf) {
        if (avail < 2 || (s[1] & 0xc0) != 0x80) return 0;
        return 2;
    }
    if (b >= 0xe0 && b <= 0xef) {
        if (avail < 3 || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80) return 0;
        if (b == 0xe0 && s[1] < 0xa0) return 0;  /* overlong */
        if (b == 0xed && s[1] >= 0xa0) return 0; /* UTF-16 surrogate */
        return 3;
    }
    if (b >= 0xf0 && b <= 0xf4) {
        if (avail < 4 || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 ||
            (s[3] & 0xc0) != 0x80)
            return 0;
        if (b == 0xf0 && s[1] < 0x90) return 0;  /* overlong */
        if (b == 0xf4 && s[1] >= 0x90) return 0; /* past U+10FFFF */
        return 4;
    }
    return 0;
}

int trp_utf8_valid(const uint8_t *s, size_t len)
{
    size_t i = 0;

    while (i < len) {
        size_t n = utf8_seq(s + i, len - i);
        if (n == 0) return 0;
        i += n;
    }
    return 1;
}

size_t trp__utf8_put(uint32_t cp, char out[4])
{
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xc0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3f));
        return 2;
    }
    if (cp >= 0xd800 && cp <= 0xdfff) return 0;
    if (cp < 0x10000) {
        out[0] = (char)(0xe0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[2] = (char)(0x80 | (cp & 0x3f));
        return 3;
    }
    if (cp <= 0x10ffff) {
        out[0] = (char)(0xf0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[3] = (char)(0x80 | (cp & 0x3f));
        return 4;
    }
    return 0;
}

/* ---- Reader ----------------------------------------------------------- */

typedef struct {
    const char *p;
    const char *end;
} cursor;

static void skip_ws(cursor *c)
{
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
        c->p++;
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

static trp_err_t parse_string(cursor *c)
{
    c->p++; /* opening quote */
    while (c->p < c->end) {
        uint8_t ch = (uint8_t)*c->p;
        if (ch == '"') {
            c->p++;
            return TRP_OK;
        }
        if (ch == '\\') {
            uint32_t unused;
            c->p++;
            if (c->p >= c->end) return TRP_ERR_INVALID;
            switch (*c->p) {
            case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
                c->p++;
                break;
            case 'u':
                if (c->end - c->p < 5 || !hex4(c->p + 1, &unused)) return TRP_ERR_INVALID;
                c->p += 5;
                break;
            default:
                return TRP_ERR_INVALID;
            }
        } else if (ch < 0x20) {
            return TRP_ERR_INVALID;
        } else {
            size_t n = utf8_seq((const uint8_t *)c->p, (size_t)(c->end - c->p));
            if (n == 0) return TRP_ERR_INVALID;
            c->p += n;
        }
    }
    return TRP_ERR_INVALID;
}

static int is_digit(char ch)
{
    return ch >= '0' && ch <= '9';
}

static trp_err_t parse_number(cursor *c)
{
    if (c->p < c->end && *c->p == '-') c->p++;
    if (c->p >= c->end) return TRP_ERR_INVALID;
    if (*c->p == '0') {
        c->p++;
    } else if (*c->p >= '1' && *c->p <= '9') {
        while (c->p < c->end && is_digit(*c->p)) c->p++;
    } else {
        return TRP_ERR_INVALID;
    }
    if (c->p < c->end && *c->p == '.') {
        c->p++;
        if (c->p >= c->end || !is_digit(*c->p)) return TRP_ERR_INVALID;
        while (c->p < c->end && is_digit(*c->p)) c->p++;
    }
    if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
        c->p++;
        if (c->p < c->end && (*c->p == '+' || *c->p == '-')) c->p++;
        if (c->p >= c->end || !is_digit(*c->p)) return TRP_ERR_INVALID;
        while (c->p < c->end && is_digit(*c->p)) c->p++;
    }
    return TRP_OK;
}

static trp_err_t parse_literal(cursor *c, const char *word)
{
    size_t n = strlen(word);

    if ((size_t)(c->end - c->p) < n || memcmp(c->p, word, n) != 0) return TRP_ERR_INVALID;
    c->p += n;
    return TRP_OK;
}

static trp_err_t parse_value(cursor *c, int depth, trp_json *out);

static trp_err_t parse_container(cursor *c, int depth, char close, int is_object)
{
    trp_json item;
    trp_err_t err;

    if (depth >= TRP_JSON_MAX_DEPTH) return TRP_ERR_INVALID;
    c->p++; /* opening bracket */
    skip_ws(c);
    if (c->p < c->end && *c->p == close) {
        c->p++;
        return TRP_OK;
    }
    for (;;) {
        skip_ws(c);
        if (is_object) {
            if (c->p >= c->end || *c->p != '"') return TRP_ERR_INVALID;
            if ((err = parse_string(c)) != TRP_OK) return err;
            skip_ws(c);
            if (c->p >= c->end || *c->p != ':') return TRP_ERR_INVALID;
            c->p++;
        }
        if ((err = parse_value(c, depth + 1, &item)) != TRP_OK) return err;
        skip_ws(c);
        if (c->p >= c->end) return TRP_ERR_INVALID;
        if (*c->p == ',') {
            c->p++;
            continue;
        }
        if (*c->p == close) {
            c->p++;
            return TRP_OK;
        }
        return TRP_ERR_INVALID;
    }
}

static trp_err_t parse_value(cursor *c, int depth, trp_json *out)
{
    const char *start;
    trp_err_t err;

    skip_ws(c);
    if (c->p >= c->end) return TRP_ERR_INVALID;
    start = c->p;
    switch (*c->p) {
    case '{':
        out->type = TRP_JSON_OBJECT;
        err = parse_container(c, depth, '}', 1);
        break;
    case '[':
        out->type = TRP_JSON_ARRAY;
        err = parse_container(c, depth, ']', 0);
        break;
    case '"':
        out->type = TRP_JSON_STRING;
        err = parse_string(c);
        break;
    case 't':
        out->type = TRP_JSON_TRUE;
        err = parse_literal(c, "true");
        break;
    case 'f':
        out->type = TRP_JSON_FALSE;
        err = parse_literal(c, "false");
        break;
    case 'n':
        out->type = TRP_JSON_NULL;
        err = parse_literal(c, "null");
        break;
    default:
        out->type = TRP_JSON_NUMBER;
        err = parse_number(c);
        break;
    }
    if (err != TRP_OK) return err;
    out->ptr = start;
    out->len = (size_t)(c->p - start);
    return TRP_OK;
}

trp_err_t trp_json_parse(const char *text, size_t len, trp_json *root)
{
    cursor c;
    trp_err_t err;

    c.p = text;
    c.end = text + len;
    if ((err = parse_value(&c, 0, root)) != TRP_OK) return err;
    skip_ws(&c);
    return c.p == c.end ? TRP_OK : TRP_ERR_INVALID;
}

/* Unescape the inside of a JSON string literal (without its quotes). */
static trp_err_t unescape(const char *raw, size_t raw_len, char *out, size_t out_cap,
                          size_t *out_len)
{
    size_t i = 0, o = 0;

    if (out_cap == 0) return TRP_ERR_BUFFER;
    while (i < raw_len) {
        char buf[4];
        const char *src = buf;
        size_t n = 1;

        if (raw[i] != '\\') {
            src = raw + i;
            i++;
        } else {
            char e;
            if (i + 1 >= raw_len) return TRP_ERR_INVALID;
            e = raw[i + 1];
            i += 2;
            switch (e) {
            case '"': buf[0] = '"'; break;
            case '\\': buf[0] = '\\'; break;
            case '/': buf[0] = '/'; break;
            case 'b': buf[0] = '\b'; break;
            case 'f': buf[0] = '\f'; break;
            case 'n': buf[0] = '\n'; break;
            case 'r': buf[0] = '\r'; break;
            case 't': buf[0] = '\t'; break;
            case 'u': {
                uint32_t cp, lo;
                if (i + 4 > raw_len || !hex4(raw + i, &cp)) return TRP_ERR_INVALID;
                i += 4;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (i + 6 > raw_len || raw[i] != '\\' || raw[i + 1] != 'u' ||
                        !hex4(raw + i + 2, &lo) || lo < 0xdc00 || lo > 0xdfff)
                        return TRP_ERR_INVALID;
                    i += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                n = trp__utf8_put(cp, buf);
                if (n == 0) return TRP_ERR_INVALID; /* lone surrogate */
                break;
            }
            default:
                return TRP_ERR_INVALID;
            }
        }
        if (out_cap - o < n + 1) return TRP_ERR_BUFFER;
        memcpy(out + o, src, n);
        o += n;
    }
    out[o] = '\0';
    if (out_len) *out_len = o;
    return TRP_OK;
}

static int key_equals(const char *raw, size_t raw_len, const char *key)
{
    char buf[128];
    size_t n;

    if (unescape(raw, raw_len, buf, sizeof(buf), &n) != TRP_OK) return 0;
    return n == strlen(key) && memcmp(buf, key, n) == 0;
}

trp_err_t trp_json_get(const trp_json *object, const char *key, trp_json *out)
{
    cursor c;
    trp_json value;
    int found = 0;
    trp_err_t err;

    if (object->type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;
    c.p = object->ptr + 1;
    c.end = object->ptr + object->len;
    skip_ws(&c);
    if (c.p < c.end && *c.p == '}') return TRP_ERR_NOT_FOUND;
    for (;;) {
        const char *key_start;
        size_t key_len;

        skip_ws(&c);
        if (c.p >= c.end || *c.p != '"') return TRP_ERR_INVALID;
        key_start = c.p + 1;
        if ((err = parse_string(&c)) != TRP_OK) return err;
        key_len = (size_t)(c.p - key_start - 1);
        skip_ws(&c);
        if (c.p >= c.end || *c.p != ':') return TRP_ERR_INVALID;
        c.p++;
        if ((err = parse_value(&c, 1, &value)) != TRP_OK) return err;
        if (key_equals(key_start, key_len, key)) {
            if (found) return TRP_ERR_INVALID; /* duplicate key */
            *out = value;
            found = 1;
        }
        skip_ws(&c);
        if (c.p < c.end && *c.p == ',') {
            c.p++;
            continue;
        }
        if (c.p < c.end && *c.p == '}') break;
        return TRP_ERR_INVALID;
    }
    return found ? TRP_OK : TRP_ERR_NOT_FOUND;
}

trp_err_t trp_json_next(const trp_json *array, size_t *pos, trp_json *out)
{
    cursor c;
    trp_err_t err;

    if (array->type != TRP_JSON_ARRAY || array->len < 2 || *pos >= array->len) return TRP_ERR_INVALID;
    c.p = array->ptr + (*pos == 0 ? 1 : *pos);
    c.end = array->ptr + array->len;
    skip_ws(&c);
    if (c.p < c.end && *c.p == ',' && *pos != 0) {
        c.p++;
        skip_ws(&c);
    }
    if (c.p >= c.end || *c.p == ']') return TRP_ERR_NOT_FOUND;
    if ((err = parse_value(&c, 1, out)) != TRP_OK) return err;
    *pos = (size_t)(c.p - array->ptr);
    return TRP_OK;
}

trp_err_t trp_json_get_string(const trp_json *value, char *out, size_t out_cap, size_t *out_len)
{
    if (value->type != TRP_JSON_STRING || value->len < 2) return TRP_ERR_INVALID;
    return unescape(value->ptr + 1, value->len - 2, out, out_cap, out_len);
}

trp_err_t trp_json_get_uint64(const trp_json *value, uint64_t *out)
{
    uint64_t v = 0;
    size_t i;

    if (value->type != TRP_JSON_NUMBER || value->len == 0) return TRP_ERR_INVALID;
    if (value->len > 1 && value->ptr[0] == '0') return TRP_ERR_INVALID;
    for (i = 0; i < value->len; i++) {
        unsigned d;
        if (!is_digit(value->ptr[i])) return TRP_ERR_INVALID; /* sign, fraction or exponent */
        d = (unsigned)(value->ptr[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return TRP_ERR_INVALID;
        v = v * 10 + d;
    }
    *out = v;
    return TRP_OK;
}

trp_err_t trp_json_get_bool(const trp_json *value, int *out)
{
    if (value->type == TRP_JSON_TRUE) *out = 1;
    else if (value->type == TRP_JSON_FALSE) *out = 0;
    else return TRP_ERR_INVALID;
    return TRP_OK;
}

/* ---- Writer ----------------------------------------------------------- */

void trp_jw_init(trp_json_writer *w, char *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = cap ? TRP_OK : TRP_ERR_BUFFER;
    w->has_items = 0;
    w->depth = 0;
}

/* Always keeps one byte free for the final NUL. */
static void put(trp_json_writer *w, const char *s, size_t n)
{
    if (w->err != TRP_OK) return;
    if (w->cap - w->len < n + 1) {
        w->err = TRP_ERR_BUFFER;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}

static void put_char(trp_json_writer *w, char ch)
{
    put(w, &ch, 1);
}

static void put_escaped(trp_json_writer *w, const char *s, size_t len)
{
    static const char HEX_DIGITS[] = "0123456789abcdef";
    size_t i;

    put_char(w, '"');
    for (i = 0; i < len; i++) {
        uint8_t ch = (uint8_t)s[i];
        switch (ch) {
        case '"': put(w, "\\\"", 2); break;
        case '\\': put(w, "\\\\", 2); break;
        case '\b': put(w, "\\b", 2); break;
        case '\f': put(w, "\\f", 2); break;
        case '\n': put(w, "\\n", 2); break;
        case '\r': put(w, "\\r", 2); break;
        case '\t': put(w, "\\t", 2); break;
        default:
            if (ch < 0x20) {
                char esc[6] = {'\\', 'u', '0', '0', HEX_DIGITS[ch >> 4], HEX_DIGITS[ch & 0x0f]};
                put(w, esc, sizeof(esc));
            } else {
                put_char(w, (char)ch);
            }
        }
    }
    put_char(w, '"');
}

void trp_jw_object_begin(trp_json_writer *w)
{
    put_char(w, '{');
    if (w->err != TRP_OK) return;
    if (w->depth >= 31) {
        w->err = TRP_ERR_INVALID;
        return;
    }
    w->depth++;
    w->has_items &= ~(1u << w->depth);
}

void trp_jw_object_end(trp_json_writer *w)
{
    put_char(w, '}');
    if (w->err == TRP_OK && w->depth > 0) w->depth--;
}

void trp_jw_key(trp_json_writer *w, const char *key)
{
    if (w->has_items & (1u << w->depth)) put_char(w, ',');
    w->has_items |= 1u << w->depth;
    put_escaped(w, key, strlen(key));
    put_char(w, ':');
}

void trp_jw_string(trp_json_writer *w, const char *s, size_t len)
{
    put_escaped(w, s, len);
}

void trp_jw_raw(trp_json_writer *w, const char *json, size_t len)
{
    put(w, json, len);
}

trp_err_t trp_jw_finish(trp_json_writer *w)
{
    if (w->err != TRP_OK) return w->err;
    w->buf[w->len] = '\0';
    return TRP_OK;
}

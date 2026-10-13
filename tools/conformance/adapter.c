/*
 * Adapter for the tempoxyz/mpp-tools conformance runner.
 *
 * Reads one JSON request ({"schema":1,"op":...,"input":...}) from stdin and
 * writes one JSON response to stdout, as conformance/HARNESS_SPEC.md
 * describes. Transponder is a client, so it implements the client-side
 * operations (challenge.parse, credential.format, receipt.parse, base64url),
 * and for the runner's round trips also the server-side formatting ones
 * (challenge.format, challenge.id, credential.parse, receipt.format), which
 * live only here, not in the library. Everything else answers
 * unsupported_operation. `adapter --self-test` checks the HMAC against RFC 4231.
 *
 * This is a host tool, so unlike the library it allocates freely.
 */

#define _POSIX_C_SOURCE 200809L /* strncasecmp under -std=c99 on glibc */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/credential.h"
#include "transponder/json.h"
#include "transponder/receipt.h"

#define MAX_INPUT (4 * 1024 * 1024)

static trp_json_writer out;
static char *out_buf;

static void finish_and_print(void)
{
    if (trp_jw_finish(&out) != TRP_OK) {
        printf("{\"ok\":false,\"error\":{\"type\":\"unknown_error\",\"message\":\"response too large\"}}\n");
        return;
    }
    printf("%s\n", out_buf);
}

static int fail(const char *type, const char *message)
{
    trp_jw_init(&out, out_buf, MAX_INPUT * 2);
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "ok");
    trp_jw_raw(&out, "false", 5);
    trp_jw_key(&out, "error");
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "type");
    trp_jw_string(&out, type, strlen(type));
    trp_jw_key(&out, "message");
    trp_jw_string(&out, message, strlen(message));
    trp_jw_object_end(&out);
    trp_jw_object_end(&out);
    finish_and_print();
    return 0;
}

/* Starts {"ok":true,"value": ; the caller writes the value and calls succeed_end(). */
static void succeed_begin(void)
{
    trp_jw_init(&out, out_buf, MAX_INPUT * 2);
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "ok");
    trp_jw_raw(&out, "true", 4);
    trp_jw_key(&out, "value");
}

static int succeed_end(void)
{
    trp_jw_object_end(&out);
    finish_and_print();
    return 0;
}

/* A string member of `obj`, unescaped into a fresh allocation; NULL if absent or not a string. */
static char *get_string(const trp_json *obj, const char *key, size_t *len)
{
    trp_json v;
    char *buf;

    if (trp_json_get(obj, key, &v) != TRP_OK || v.type != TRP_JSON_STRING) return NULL;
    buf = malloc(v.len + 1);
    if (!buf || trp_json_get_string(&v, buf, v.len + 1, len) != TRP_OK) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* ---- RFC 8785 (JCS) for the values these vectors use ------------------ */

typedef struct {
    char *key;
    size_t key_len;
    trp_json value;
} member;

static int cmp_members(const void *a, const void *b)
{
    const member *x = (const member *)a, *y = (const member *)b;
    size_t n = x->key_len < y->key_len ? x->key_len : y->key_len;
    int c = memcmp(x->key, y->key, n);
    if (c != 0) return c;
    return x->key_len < y->key_len ? -1 : x->key_len > y->key_len;
}

/*
 * Keys sort by UTF-8 bytes, which matches JCS's UTF-16 order for everything
 * outside the surrogate range. Only integer numbers are supported.
 */
static int jcs(trp_json_writer *w, const trp_json *v)
{
    size_t pos = 0, i, n = 0, cap = 16;
    trp_json item;

    switch (v->type) {
    case TRP_JSON_NULL:
    case TRP_JSON_TRUE:
    case TRP_JSON_FALSE:
        trp_jw_raw(w, v->ptr, v->len);
        return 1;
    case TRP_JSON_NUMBER:
        for (i = 0; i < v->len; i++)
            if (v->ptr[i] == '.' || v->ptr[i] == 'e' || v->ptr[i] == 'E') return 0;
        trp_jw_raw(w, v->ptr, v->len);
        return 1;
    case TRP_JSON_STRING: {
        size_t len;
        char *s = malloc(v->len + 1);
        if (!s || trp_json_get_string(v, s, v->len + 1, &len) != TRP_OK) {
            free(s);
            return 0;
        }
        trp_jw_string(w, s, len);
        free(s);
        return 1;
    }
    case TRP_JSON_ARRAY:
        trp_jw_raw(w, "[", 1);
        while (trp_json_next(v, &pos, &item) == TRP_OK) {
            if (n++) trp_jw_raw(w, ",", 1);
            if (!jcs(w, &item)) return 0;
        }
        trp_jw_raw(w, "]", 1);
        return 1;
    case TRP_JSON_OBJECT: {
        /* Walk the members by scanning the object text with the reader's iterator trick:
         * wrap each "key":value pair through trp_json_get is O(n^2), so parse directly. */
        member *members = malloc(cap * sizeof(member));
        const char *p = v->ptr + 1, *end = v->ptr + v->len - 1;
        int ok = 1;

        while (members && p < end) {
            trp_json key, val;
            const char *q;
            size_t klen;

            while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
            if (p >= end) break;
            /* The key string: find its end by parsing it as a JSON value. */
            q = p + 1;
            while (q < end && *q != '"') q += (*q == '\\') ? 2 : 1;
            if (trp_json_parse(p, (size_t)(q + 1 - p), &key) != TRP_OK) {
                ok = 0;
                break;
            }
            p = q + 1;
            while (p < end && *p != ':') p++;
            p++;
            while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
            /* The value: grow until it parses. Values are short in these vectors. */
            for (q = p + 1; q <= end; q++)
                if (trp_json_parse(p, (size_t)(q - p), &val) == TRP_OK &&
                    (q == end || *q == ',' || *q == ' ' || *q == '\n' || *q == '\r' || *q == '\t'))
                    break;
            if (q > end) {
                ok = 0;
                break;
            }
            if (n == cap) {
                member *bigger = realloc(members, (cap *= 2) * sizeof(member));
                if (!bigger) {
                    ok = 0;
                    break;
                }
                members = bigger;
            }
            members[n].key = malloc(key.len + 1);
            if (!members[n].key ||
                trp_json_get_string(&key, members[n].key, key.len + 1, &klen) != TRP_OK) {
                ok = 0;
                break;
            }
            members[n].key_len = klen;
            members[n].value = val;
            n++;
            p = q;
        }
        if (!members) return 0;
        if (ok) {
            qsort(members, n, sizeof(member), cmp_members);
            trp_jw_raw(w, "{", 1);
            for (i = 0; i < n && ok; i++) {
                if (i) trp_jw_raw(w, ",", 1);
                trp_jw_string(w, members[i].key, members[i].key_len);
                trp_jw_raw(w, ":", 1);
                ok = jcs(w, &members[i].value);
            }
            trp_jw_raw(w, "}", 1);
        }
        for (i = 0; i < n; i++) free(members[i].key);
        free(members);
        return ok;
    }
    }
    return 0;
}

/* ---- SHA-256 and HMAC (FIPS 180-4, RFC 2104), only for challenge.id ---- */

typedef struct {
    uint32_t h[8];
    uint8_t block[64];
    size_t used;
    uint64_t total;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(c->h, IV, sizeof(IV));
    c->used = 0;
    c->total = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->total += n;
    while (n--) {
        c->block[c->used++] = *p++;
        if (c->used == 64) {
            sha256_block(c, c->block);
            c->used = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t md[32])
{
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80, zero = 0, len[8];
    int i;

    sha256_update(c, &pad, 1);
    while (c->used != 56) sha256_update(c, &zero, 1);
    for (i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, len, 8);
    for (i = 0; i < 8; i++) {
        md[4 * i] = (uint8_t)(c->h[i] >> 24);
        md[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        md[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        md[4 * i + 3] = (uint8_t)c->h[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                        uint8_t md[32])
{
    uint8_t k[64] = {0}, ipad[64], opad[64], inner[32];
    sha256_ctx c;
    int i;

    if (key_len > 64) {
        sha256_init(&c);
        sha256_update(&c, key, key_len);
        sha256_final(&c, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, md);
}

/* Built-in check against RFC 4231 test case 2, run by `adapter --self-test`. */
static int hmac_self_test(void)
{
    static const uint8_t want[32] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
                                     0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
                                     0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
    const char *data = "what do ya want for nothing?";
    uint8_t got[32];
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)data, strlen(data), got);
    return memcmp(got, want, 32) == 0;
}

/* base64url(JCS(request)) for a request object; NULL on failure. */
static char *encode_request(const trp_json *req)
{
    trp_json_writer w;
    size_t cap = 2 * req->len + 64;
    char *json = malloc(cap), *b64;

    trp_jw_init(&w, json, cap);
    if (!jcs(&w, req) || trp_jw_finish(&w) != TRP_OK) return NULL;
    b64 = malloc(TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
    trp_base64url_encode((const uint8_t *)json, w.len, b64, TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
    free(json);
    return b64;
}

static int is_default_header(const char *h)
{
    const char *a = "authorization";
    size_t i;
    if (strlen(h) != strlen(a)) return 0;
    for (i = 0; a[i]; i++)
        if ((h[i] | 0x20) != a[i]) return 0;
    return 1;
}

/* ---- operations ------------------------------------------------------- */

static int op_challenge_id(const trp_json *input)
{
    static const char *const OPTIONAL[] = {"expires", "digest"};
    trp_json req;
    size_t len, i, n = 0, cap;
    char *secret = get_string(input, "secretKey", &len), *s, *msg, *b64;
    uint8_t mac[32];
    char id[64];

    if (!secret) return fail("generation_error", "missing secretKey");
    if (len < 32) return fail("generation_error", "secret key must be at least 32 bytes");
    if (trp_json_get(input, "request", &req) != TRP_OK || req.type != TRP_JSON_OBJECT)
        return fail("generation_error", "request must be an object");
    if (!(b64 = encode_request(&req))) return fail("generation_error", "request cannot be canonicalized");

    cap = input->len + strlen(b64) + 64;
    msg = malloc(cap);
#define APPEND(str) do { size_t l_ = strlen(str); memcpy(msg + n, str, l_); n += l_; } while (0)
    s = get_string(input, "realm", &len);  APPEND(s ? s : ""); APPEND("|");
    s = get_string(input, "method", &len); APPEND(s ? s : ""); APPEND("|");
    s = get_string(input, "intent", &len); APPEND(s ? s : ""); APPEND("|");
    APPEND(b64);
    for (i = 0; i < 2; i++) {
        s = get_string(input, OPTIONAL[i], &len);
        APPEND("|");
        APPEND(s ? s : "");
    }
    s = get_string(input, "header", &len);
    if (s && !is_default_header(s)) {
        APPEND("|");
        APPEND(s);
    }
    s = get_string(input, "opaque", &len);
    APPEND("|");
    APPEND(s ? s : "");
#undef APPEND

    hmac_sha256((const uint8_t *)secret, strlen(secret), (const uint8_t *)msg, n, mac);
    trp_base64url_encode(mac, 32, id, sizeof(id));
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "id");
    trp_jw_string(&out, id, strlen(id));
    trp_jw_object_end(&out);
    return succeed_end();
}

/*
 * One auth-param as mppx writes it: backslash and quote escaped, and every
 * UTF-16 code unit from U+0100 up written as \uXXXX so the header stays a
 * Latin-1 byte string. CR and LF are refused.
 */
static int auth_param(char *dst, size_t *n, const char *name, const char *value)
{
    size_t i = 0, len = strlen(value);

    *n += (size_t)sprintf(dst + *n, "%s%s=\"", *n > 8 ? ", " : "", name);
    while (i < len) {
        uint8_t c = (uint8_t)value[i];
        uint32_t cp;
        size_t k;

        if (c == '\r' || c == '\n') return 0;
        if (c < 0x80) {
            if (c == '\\' || c == '"') dst[(*n)++] = '\\';
            dst[(*n)++] = (char)c;
            i++;
            continue;
        }
        /* Decode one UTF-8 sequence (the input already passed JSON's UTF-8 check). */
        k = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : 2;
        cp = c & (k == 4 ? 0x07 : k == 3 ? 0x0f : 0x1f);
        for (size_t j = 1; j < k; j++) cp = (cp << 6) | ((uint8_t)value[i + j] & 0x3f);
        if (cp < 0x100) {
            memcpy(dst + *n, value + i, k); /* Latin-1 stays as is */
            *n += k;
        } else if (cp < 0x10000) {
            *n += (size_t)sprintf(dst + *n, "\\u%04x", cp);
        } else {
            cp -= 0x10000;
            *n += (size_t)sprintf(dst + *n, "\\u%04x\\u%04x", 0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
        }
        i += k;
    }
    dst[(*n)++] = '"';
    dst[*n] = '\0';
    return 1;
}

static int op_challenge_format(const trp_json *input)
{
    static const char *const ORDER[] = {"id", "realm", "method", "intent"};
    static const char *const OPTIONAL[] = {"description", "digest", "expires", "header", "opaque"};
    trp_json req;
    size_t len, n, i;
    char *hdr, *s, *b64;

    s = get_string(input, "id", &len);
    if (!s || len == 0) return fail("format_error", "id must be a non-empty string");
    if (trp_json_get(input, "request", &req) != TRP_OK || req.type != TRP_JSON_OBJECT)
        return fail("format_error", "request must be an object");
    if (!(b64 = encode_request(&req))) return fail("format_error", "request cannot be canonicalized");

    hdr = malloc(16 * (input->len + strlen(b64)) + 64);
    n = (size_t)sprintf(hdr, "Payment ");
    for (i = 0; i < 4; i++) {
        s = get_string(input, ORDER[i], &len);
        if (!s) return fail("format_error", "missing required field");
        if (!auth_param(hdr, &n, ORDER[i], s)) return fail("format_error", "CR or LF in a value");
    }
    if (!auth_param(hdr, &n, "request", b64)) return fail("format_error", "bad request");
    for (i = 0; i < 5; i++) {
        s = get_string(input, OPTIONAL[i], &len);
        if (!s) continue;
        if (i == 3 && is_default_header(s)) continue; /* the implicit default */
        if (!auth_param(hdr, &n, OPTIONAL[i], s)) return fail("format_error", "CR or LF in a value");
    }
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "header");
    trp_jw_string(&out, hdr, n);
    trp_jw_object_end(&out);
    return succeed_end();
}

static int op_credential_parse(const trp_json *input)
{
    static const char *const FIELDS[] = {"id", "realm", "method", "intent", "description",
                                         "digest", "expires", "header", "opaque"};
    size_t len, n, i, rlen;
    char *header = get_string(input, "header", &len), *json, *req_text;
    const char *b64;
    trp_json root, ch, payload, src, req, v;
    uint8_t *req_json;

    if (!header) return fail("parse_error", "input.header must be a string");
    b64 = header;
    while (*b64 == ' ' || *b64 == '\t') b64++;
    if (strncasecmp(b64, "payment", 7) != 0 || (b64[7] != ' ' && b64[7] != '\t'))
        return fail("parse_error", "missing Payment scheme");
    b64 += 7;
    while (*b64 == ' ' || *b64 == '\t') b64++;
    json = malloc(strlen(b64) + 1);
    if (trp_base64url_decode(b64, strlen(b64), (uint8_t *)json, strlen(b64) + 1, &n) != TRP_OK ||
        !trp_utf8_valid((const uint8_t *)json, n) || trp_json_parse(json, n, &root) != TRP_OK ||
        root.type != TRP_JSON_OBJECT)
        return fail("parse_error", "credential is not base64url JSON object");
    if (trp_json_get(&root, "challenge", &ch) != TRP_OK || ch.type != TRP_JSON_OBJECT)
        return fail("parse_error", "missing challenge");
    if (trp_json_get(&root, "payload", &payload) != TRP_OK || payload.type != TRP_JSON_OBJECT)
        return fail("parse_error", "missing payload");
    for (i = 0; i < 4; i++) {
        char *s = get_string(&ch, FIELDS[i], &len);
        if (!s || (i == 0 && len == 0)) return fail("parse_error", "challenge is missing a required field");
    }
    req_text = get_string(&ch, "request", &len);
    if (!req_text) return fail("parse_error", "challenge.request must be a string");
    req_json = malloc(len + 1);
    if (trp_base64url_decode(req_text, len, req_json, len + 1, &rlen) != TRP_OK ||
        trp_json_parse((const char *)req_json, rlen, &req) != TRP_OK || req.type != TRP_JSON_OBJECT)
        return fail("parse_error", "challenge.request is not base64url JSON object");

    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "challenge");
    trp_jw_object_begin(&out);
    for (i = 0; i < 9; i++) {
        if (trp_json_get(&ch, FIELDS[i], &v) == TRP_OK) {
            trp_jw_key(&out, FIELDS[i]);
            trp_jw_raw(&out, v.ptr, v.len);
        }
    }
    trp_jw_key(&out, "request");
    trp_jw_raw(&out, req.ptr, req.len);
    trp_jw_object_end(&out);
    trp_jw_key(&out, "payload");
    trp_jw_raw(&out, payload.ptr, payload.len);
    if (trp_json_get(&root, "source", &src) == TRP_OK) {
        trp_jw_key(&out, "source");
        trp_jw_raw(&out, src.ptr, src.len);
    }
    trp_jw_object_end(&out);
    return succeed_end();
}

static int op_receipt_format(const trp_json *input)
{
    trp_json_writer w;
    size_t cap = 2 * input->len + 64;
    char *json = malloc(cap), *b64;
    static const char *const REQUIRED[] = {"status", "timestamp", "reference"};
    size_t i, len;

    for (i = 0; i < 3; i++)
        if (!get_string(input, REQUIRED[i], &len) || len == 0) return fail("format_error", "missing field");
    trp_jw_init(&w, json, cap);
    if (!jcs(&w, input) || trp_jw_finish(&w) != TRP_OK) return fail("format_error", "cannot encode");
    b64 = malloc(TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
    trp_base64url_encode((const uint8_t *)json, w.len, b64, TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "header");
    trp_jw_string(&out, b64, strlen(b64));
    trp_jw_object_end(&out);
    return succeed_end();
}

static int op_base64url_encode(const trp_json *input)
{
    size_t len;
    char *text = get_string(input, "text", &len), *enc;

    if (!text) return fail("encoding_error", "input.text must be a string");
    enc = malloc(TRP_BASE64URL_ENCODED_LEN(len) + 1);
    trp_base64url_encode((const uint8_t *)text, len, enc, TRP_BASE64URL_ENCODED_LEN(len) + 1);
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "text");
    trp_jw_string(&out, enc, strlen(enc));
    trp_jw_object_end(&out);
    return succeed_end();
}

static int op_base64url_decode(const trp_json *input)
{
    size_t len, n;
    char *text = get_string(input, "text", &len);
    uint8_t *dec;

    if (!text) return fail("encoding_error", "input.text must be a string");
    dec = malloc(len + 1);
    if (trp_base64url_decode(text, len, dec, len + 1, &n) != TRP_OK)
        return fail("encoding_error", "invalid base64url");
    if (!trp_utf8_valid(dec, n)) return fail("encoding_error", "decoded bytes are not UTF-8");
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "text");
    trp_jw_string(&out, (const char *)dec, n);
    trp_jw_object_end(&out);
    return succeed_end();
}

static void put_opt(const char *key, trp_str s)
{
    if (!s.ptr) return;
    trp_jw_key(&out, key);
    trp_jw_string(&out, s.ptr, s.len);
}

static int op_challenge_parse(const trp_json *input)
{
    size_t len;
    char *header = get_string(input, "header", &len), *scratch;
    trp_challenge ch;
    trp_err_t err;

    if (!header) return fail("parse_error", "input.header must be a string");
    scratch = malloc(2 * len + 16);
    if ((err = trp_challenge_parse(header, len, &ch, scratch, 2 * len + 16)) != TRP_OK)
        return fail("parse_error", err == TRP_ERR_UNSUPPORTED ? "unsupported challenge" : "invalid challenge");
    succeed_begin();
    trp_jw_object_begin(&out);
    put_opt("id", ch.id);
    put_opt("realm", ch.realm);
    put_opt("method", ch.method);
    put_opt("intent", ch.intent);
    trp_jw_key(&out, "request");
    trp_jw_raw(&out, ch.request_json.ptr, ch.request_json.len);
    put_opt("description", ch.description);
    put_opt("digest", ch.digest);
    put_opt("expires", ch.expires);
    put_opt("header", ch.header);
    put_opt("opaque", ch.opaque);
    trp_jw_object_end(&out);
    return succeed_end();
}

static trp_str str_of(char *s, size_t len)
{
    trp_str r;
    r.ptr = s;
    r.len = s ? len : 0;
    return r;
}

static int op_credential_format(const trp_json *input)
{
    trp_json chj, req, payload;
    trp_challenge ch;
    trp_json_writer w;
    char *req_json, *req_b64, *source, *header, *scratch;
    size_t len, cap;

    if (trp_json_get(input, "challenge", &chj) != TRP_OK || chj.type != TRP_JSON_OBJECT)
        return fail("format_error", "challenge must be an object");
    if (trp_json_get(input, "payload", &payload) != TRP_OK || payload.type != TRP_JSON_OBJECT)
        return fail("format_error", "payload must be an object");

    memset(&ch, 0, sizeof(ch));
#define FIELD(name) do { char *s_ = get_string(&chj, #name, &len); ch.name = str_of(s_, len); } while (0)
    FIELD(id);
    FIELD(realm);
    FIELD(method);
    FIELD(intent);
    FIELD(description);
    FIELD(digest);
    FIELD(expires);
    FIELD(header);
    FIELD(opaque);
#undef FIELD

    /* request: an object to encode with JCS, or an already-encoded string. */
    if (trp_json_get(&chj, "request", &req) != TRP_OK) return fail("format_error", "missing request");
    if (req.type == TRP_JSON_STRING) {
        char *s = get_string(&chj, "request", &len);
        ch.request = str_of(s, len);
    } else {
        cap = 2 * req.len + 64;
        req_json = malloc(cap);
        trp_jw_init(&w, req_json, cap);
        if (!jcs(&w, &req) || trp_jw_finish(&w) != TRP_OK)
            return fail("format_error", "request cannot be canonicalized");
        req_b64 = malloc(TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
        trp_base64url_encode((const uint8_t *)req_json, w.len, req_b64, TRP_BASE64URL_ENCODED_LEN(w.len) + 1);
        ch.request = str_of(req_b64, strlen(req_b64));
    }

    source = get_string(input, "source", &len);
    cap = 4 * (input->len + 1024);
    header = malloc(cap);
    scratch = malloc(cap);
    if (trp_credential_encode(&ch, payload.ptr, payload.len, source, header, cap, scratch, cap) != TRP_OK)
        return fail("format_error", "invalid credential");
    succeed_begin();
    trp_jw_object_begin(&out);
    trp_jw_key(&out, "header");
    trp_jw_string(&out, header, strlen(header));
    trp_jw_object_end(&out);
    return succeed_end();
}

static int op_receipt_parse(const trp_json *input)
{
    size_t len;
    char *header = get_string(input, "header", &len), *scratch;
    trp_receipt receipt;

    if (!header) return fail("parse_error", "input.header must be a string");
    scratch = malloc(2 * len + 16);
    if (trp_receipt_parse(header, len, &receipt, scratch, 2 * len + 16) != TRP_OK)
        return fail("parse_error", "invalid receipt");
    succeed_begin();
    trp_jw_raw(&out, receipt.json.ptr, receipt.json.len);
    return succeed_end();
}

int main(int argc, char **argv)
{
    char *in = malloc(MAX_INPUT + 1), op[64];

    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) {
        puts(hmac_self_test() ? "hmac-sha256 ok" : "hmac-sha256 FAILED");
        return hmac_self_test() ? 0 : 1;
    }
    size_t len = 0, n;
    trp_json root, v, input;

    out_buf = malloc(MAX_INPUT * 2);
    if (!in || !out_buf) return 1;
    while ((n = fread(in + len, 1, MAX_INPUT - len, stdin)) > 0) len += n;
    if (trp_json_parse(in, len, &root) != TRP_OK || root.type != TRP_JSON_OBJECT)
        return fail("unknown_error", "request is not a JSON object");
    if (trp_json_get(&root, "op", &v) != TRP_OK || trp_json_get_string(&v, op, sizeof(op), NULL) != TRP_OK)
        return fail("unknown_error", "missing op");
    if (trp_json_get(&root, "input", &input) != TRP_OK) return fail("unknown_error", "missing input");

    if (strcmp(op, "challenge.parse") == 0) {
        if (input.type != TRP_JSON_OBJECT) return fail("parse_error", "input must be an object");
        return op_challenge_parse(&input);
    }
    if (strcmp(op, "credential.format") == 0) {
        if (input.type != TRP_JSON_OBJECT) return fail("format_error", "input must be an object");
        return op_credential_format(&input);
    }
    if (strcmp(op, "receipt.parse") == 0) {
        if (input.type != TRP_JSON_OBJECT) return fail("parse_error", "input must be an object");
        return op_receipt_parse(&input);
    }
    if (input.type == TRP_JSON_OBJECT) {
        if (strcmp(op, "challenge.format") == 0) return op_challenge_format(&input);
        if (strcmp(op, "challenge.id") == 0) return op_challenge_id(&input);
        if (strcmp(op, "credential.parse") == 0) return op_credential_parse(&input);
        if (strcmp(op, "receipt.format") == 0) return op_receipt_format(&input);
    }
    if (strcmp(op, "base64url.encode") == 0 && input.type == TRP_JSON_OBJECT) return op_base64url_encode(&input);
    if (strcmp(op, "base64url.decode") == 0 && input.type == TRP_JSON_OBJECT) return op_base64url_decode(&input);
    return fail("unsupported_operation", op);
}

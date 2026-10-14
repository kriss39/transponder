#include "test.h"

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/credential.h"
#include "transponder/receipt.h"
#include "conformance_vectors.h"

static char wire_buf[32 * 1024];
static char scratch[2 * sizeof(wire_buf) + 16];

static int str_matches(trp_str got, const char *want)
{
    if (want == NULL) return got.ptr == NULL;
    return got.ptr != NULL && got.len == strlen(want) && memcmp(got.ptr, want, got.len) == 0 &&
           got.ptr[got.len] == '\0';
}

static int request_field_matches(const trp_challenge *ch, const char *key, const char *want)
{
    trp_json v;
    char s[128];

    if (want == NULL) return 1;
    return trp_json_get(&ch->request_json, key, &v) == TRP_OK &&
           trp_json_get_string(&v, s, sizeof(s), NULL) == TRP_OK && strcmp(s, want) == 0;
}

static const char *build_wire(const wa_vector *v, size_t *len)
{
    size_t i, n = 0;

    if (v->wire) {
        *len = strlen(v->wire);
        return v->wire;
    }
    memcpy(wire_buf, v->prefix, strlen(v->prefix));
    n = strlen(v->prefix);
    for (i = 0; i < v->count; i++) {
        memcpy(wire_buf + n, v->repeat, strlen(v->repeat));
        n += strlen(v->repeat);
    }
    memcpy(wire_buf + n, v->suffix, strlen(v->suffix));
    n += strlen(v->suffix);
    *len = n;
    return wire_buf;
}

static void test_conformance(void)
{
    size_t i;

    for (i = 0; i < sizeof(WA_VECTORS) / sizeof(WA_VECTORS[0]); i++) {
        const wa_vector *v = &WA_VECTORS[i];
        trp_challenge ch;
        size_t len;
        const char *wire = build_wire(v, &len);
        trp_err_t err = trp_challenge_parse(wire, len, &ch, scratch, sizeof(scratch));
        int ok;

        if (!v->ok) {
            ok = err != TRP_OK;
        } else {
            ok = err == TRP_OK && str_matches(ch.id, v->id) && str_matches(ch.realm, v->realm) &&
                 str_matches(ch.method, v->method) && str_matches(ch.intent, v->intent) &&
                 str_matches(ch.description, v->description) &&
                 str_matches(ch.digest, v->digest) && str_matches(ch.expires, v->expires) &&
                 str_matches(ch.header, v->header) && str_matches(ch.opaque, v->opaque) &&
                 ch.request_json.type == TRP_JSON_OBJECT &&
                 request_field_matches(&ch, "amount", v->amount) &&
                 request_field_matches(&ch, "recipient", v->recipient);
        }
        trp_test_checks++;
        if (!ok) {
            trp_test_failures++;
            printf("  FAIL conformance www-authenticate/%s (err %d)\n", v->name, (int)err);
        }
    }
}

static void test_extra_cases(void)
{
    trp_challenge ch;
    const char *two = "Bearer realm=\"x\", Payment id=\"a\", realm=\"r\", method=\"stripe\", "
                      "intent=\"charge\", request=\"e30\", Payment id=\"b\", realm=\"r\", "
                      "method=\"tempo\", intent=\"charge\", request=\"e30\"";
    const char *alt = "Payment id=\"h\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                      "request=\"e30\", header=\"Payment-Authorization\"";
    const char *bad_header = "Payment id=\"h\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                             "request=\"e30\", header=\"X-Pay\"";
    const char *array_request = "Payment id=\"a\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                                "request=\"W10\"";
    const char *upper_method = "Payment id=\"a\", realm=\"r\", method=\"Tempo\", intent=\"charge\", "
                               "request=\"e30\"";
    size_t i, n;

    /* Several challenges in one field value: pick by method and intent. */
    CHECK(trp_challenge_select(two, strlen(two), "tempo", "charge", &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(str_matches(ch.id, "b"));
    CHECK(trp_challenge_select(two, strlen(two), NULL, NULL, &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(str_matches(ch.id, "a"));
    CHECK(trp_challenge_select(two, strlen(two), "lightning", NULL, &ch, scratch, sizeof(scratch)) ==
          TRP_ERR_NOT_FOUND);

    /* The credential field the challenge selects. */
    CHECK(trp_challenge_parse(alt, strlen(alt), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(strcmp(trp_challenge_credential_header(&ch), "Payment-Authorization") == 0);
    CHECK(trp_challenge_parse(strstr(two, "Payment"), strlen(strstr(two, "Payment")), &ch, scratch,
                              sizeof(scratch)) == TRP_OK);
    CHECK(strcmp(trp_challenge_credential_header(&ch), "Authorization") == 0);
    CHECK(trp_challenge_parse(bad_header, strlen(bad_header), &ch, scratch, sizeof(scratch)) ==
          TRP_ERR_UNSUPPORTED);

    CHECK(trp_challenge_parse(array_request, strlen(array_request), &ch, scratch, sizeof(scratch)) ==
          TRP_ERR_INVALID);
    CHECK(trp_challenge_parse(upper_method, strlen(upper_method), &ch, scratch, sizeof(scratch)) ==
          TRP_ERR_INVALID);

    /* A quote inside an unquoted value is not a token. */
    {
        const char *q = "Payment id=a\"b, realm=\"r\", method=\"tempo\", intent=\"charge\", request=\"e30\"";
        CHECK(trp_challenge_parse(q, strlen(q), &ch, scratch, sizeof(scratch)) == TRP_ERR_INVALID);
    }

    /* Raw Latin-1 header bytes are read the way JavaScript reads them, as UTF-8 out. */
    {
        const char *l1 = "Payment id=\"l\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                         "request=\"e30\", description=\"caf\xe9\"";
        CHECK(trp_challenge_parse(l1, strlen(l1), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(str_matches(ch.description, "caf\xc3\xa9"));
    }

    /*
     * mppx writes U+0080..U+00FF as raw bytes and escapes the rest, so one
     * value can mix both: only the raw byte is widened, the escape's UTF-8
     * stays as it is ("Caf\xe9 — X" from mppx 0.13.4's Challenge.serialize).
     */
    {
        const char *mixed = "Payment id=\"m\", realm=\"Caf\xe9 \\u2014 X\", method=\"tempo\", "
                            "intent=\"charge\", request=\"e30\"";
        CHECK(trp_challenge_parse(mixed, strlen(mixed), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(str_matches(ch.realm, "Caf\xc3\xa9 \xe2\x80\x94 X"));
    }

    /* Like mppx: a token value is trimmed of tabs, and empty optional parameters are absent. */
    {
        const char *tab = "Payment id=abc\t, realm=r, method=tempo, intent=charge, request=e30";
        const char *empty = "Payment id=\"e\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                            "request=\"e30\", expires=\"\", digest=\"\", description=\"\", opaque=\"\"";
        const char *lower = "Payment id=\"e\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                            "request=\"e30\", expires=\"2030-01-01t00:00:00z\"";
        uint64_t t;
        CHECK(trp_challenge_parse(tab, strlen(tab), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(str_matches(ch.id, "abc"));
        CHECK(trp_challenge_parse(empty, strlen(empty), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(!ch.expires.ptr && !ch.digest.ptr && !ch.description.ptr && !ch.opaque.ptr);
        /* RFC 3339 as mppx's z.datetime reads it: an uppercase T and Z only. */
        CHECK(trp_challenge_parse(lower, strlen(lower), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(trp_parse_rfc3339(ch.expires.ptr, ch.expires.len, &t) == TRP_ERR_INVALID);
        CHECK(trp_parse_rfc3339("2030-01-01 00:00:00Z", 20, &t) == TRP_ERR_INVALID);
        CHECK(trp_parse_rfc3339("2030-01-01T00:00:00Z", 20, &t) == TRP_OK && t == 1893456000u);
    }

    /* Too little scratch is reported, not overrun. */
    CHECK(trp_challenge_parse(alt, strlen(alt), &ch, scratch, 8) == TRP_ERR_BUFFER);

    /*
     * An unterminated quoted value full of backslashes (the mpp-tools ReDoS
     * case) is rejected in one linear pass, as mppx does.
     */
    n = (size_t)snprintf(wire_buf, sizeof(wire_buf),
                         "Payment id=\"a\", realm=\"r\", method=\"tempo\", intent=\"charge\", "
                         "request=\"e30\", fuzz=\"");
    for (i = 0; i < 12000; i++) wire_buf[n++] = '\\';
    CHECK(trp_challenge_parse(wire_buf, n, &ch, scratch, sizeof(scratch)) == TRP_ERR_INVALID);
}

/* Parse a challenge, answer it, and check that the credential echoes it exactly. */
static void test_roundtrip(void)
{
    const char *wire = "Payment id=\"ch_rt\", realm=\"api.example.com\", method=\"tempo\", "
                       "intent=\"charge\", request=\"e30\", description=\"Pay \\\"premium\\\" "
                       "\\u2014 API\", opaque=\"eyJyb3V0ZSI6Ii92MSJ9\", expires=\"2026-01-29T12:05:00Z\"";
    const char *payload = "{\"type\":\"hash\",\"hash\":\"0x01\"}";
    trp_challenge ch;
    char header[512], json_scratch[512], decoded[512];
    size_t n;
    trp_json root, chal, v;
    char s[128];

    CHECK(trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_credential_encode(&ch, payload, strlen(payload), "did:pkh:eip155:42431:0xab", header,
                                sizeof(header), json_scratch, sizeof(json_scratch)) == TRP_OK);
    CHECK(strncmp(header, "Payment ", 8) == 0);
    CHECK(trp_base64url_decode(header + 8, strlen(header + 8), (uint8_t *)decoded, sizeof(decoded),
                               &n) == TRP_OK);
    CHECK(trp_json_parse(decoded, n, &root) == TRP_OK);
    CHECK(trp_json_get(&root, "challenge", &chal) == TRP_OK);
    CHECK(trp_json_get(&chal, "description", &v) == TRP_OK &&
          trp_json_get_string(&v, s, sizeof(s), NULL) == TRP_OK &&
          strcmp(s, "Pay \"premium\" \xe2\x80\x94 API") == 0);
    CHECK(trp_json_get(&chal, "opaque", &v) == TRP_OK);
    CHECK(trp_json_get(&chal, "header", &v) == TRP_ERR_NOT_FOUND);
    CHECK(trp_json_get(&root, "source", &v) == TRP_OK);

    /* The payload must be a JSON object. */
    CHECK(trp_credential_encode(&ch, "[]", 2, NULL, header, sizeof(header), json_scratch,
                                sizeof(json_scratch)) == TRP_ERR_INVALID);
    CHECK(trp_credential_encode(&ch, payload, strlen(payload), NULL, header, 40, json_scratch,
                                sizeof(json_scratch)) == TRP_ERR_BUFFER);
}

static trp_str s_of(const char *s)
{
    trp_str out;
    out.ptr = s;
    out.len = s ? strlen(s) : 0;
    return out;
}

static void test_credential_conformance(void)
{
    size_t i;

    for (i = 0; i < sizeof(AUTH_VECTORS) / sizeof(AUTH_VECTORS[0]); i++) {
        const auth_vector *v = &AUTH_VECTORS[i];
        trp_challenge ch;
        char header[1024], json_scratch[1024];
        trp_err_t err;

        memset(&ch, 0, sizeof(ch));
        ch.id = s_of(v->id);
        ch.realm = s_of(v->realm);
        ch.method = s_of(v->method);
        ch.intent = s_of(v->intent);
        ch.request = s_of(v->request);
        ch.description = s_of(v->description);
        ch.digest = s_of(v->digest);
        ch.expires = s_of(v->expires);
        ch.header = s_of(v->header);
        ch.opaque = s_of(v->opaque);
        err = trp_credential_encode(&ch, v->payload, strlen(v->payload), v->source, header,
                                    sizeof(header), json_scratch, sizeof(json_scratch));
        trp_test_checks++;
        if (err != TRP_OK || strcmp(header, v->wire) != 0) {
            trp_test_failures++;
            printf("  FAIL conformance authorization/%s (err %d)\n    want %s\n    got  %s\n",
                   v->name, (int)err, v->wire, err == TRP_OK ? header : "");
        }
    }
}

static void test_receipt_verify(void)
{
    /* {"method":"tempo","reference":"0x" + "ab" x 32,"status":"success","timestamp":"2026-01-29T12:00:30Z"} */
    const char *wire = "eyJtZXRob2QiOiJ0ZW1wbyIsInJlZmVyZW5jZSI6IjB4YWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYiIsInN0YXR1cyI6InN1Y2Nlc3MiLCJ0aW1lc3RhbXAiOiIyMDI2LTAxLTI5VDEyOjAwOjMwWiJ9";
    uint8_t hash[32], other[32];
    trp_receipt r;

    memset(hash, 0xab, 32);
    memset(other, 0xcd, 32);
    CHECK(trp_receipt_parse(wire, strlen(wire), &r, scratch, sizeof(scratch)) == TRP_OK);
    CHECK(trp_receipt_verify(&r, "tempo", hash) == TRP_OK);
    CHECK(trp_receipt_verify(&r, "tempo", NULL) == TRP_OK);
    CHECK(trp_receipt_verify(&r, "tempo", other) == TRP_ERR_DENIED);
    CHECK(trp_receipt_verify(&r, "stripe", hash) == TRP_ERR_DENIED);
    r.status.ptr = "failed";
    r.status.len = 6;
    CHECK(trp_receipt_verify(&r, "tempo", hash) == TRP_ERR_DENIED);

    /* The scratch buffer exactly as large as the decoded JSON is reported, not overrun. */
    CHECK(trp_receipt_parse(wire, strlen(wire), &r, scratch, 140) != TRP_OK);
}

static void test_receipts(void)
{
    size_t i;

    test_receipt_verify();

    for (i = 0; i < sizeof(RECEIPT_VECTORS) / sizeof(RECEIPT_VECTORS[0]); i++) {
        const receipt_vector *v = &RECEIPT_VECTORS[i];
        trp_receipt r;
        trp_err_t err = trp_receipt_parse(v->wire, strlen(v->wire), &r, scratch, sizeof(scratch));
        int ok = v->ok ? (err == TRP_OK && str_matches(r.status, v->status) &&
                          str_matches(r.method, v->method) && str_matches(r.timestamp, v->timestamp) &&
                          str_matches(r.reference, v->reference))
                       : err != TRP_OK;
        trp_test_checks++;
        if (!ok) {
            trp_test_failures++;
            printf("  FAIL conformance receipt/%s (err %d)\n", v->name, (int)err);
        }
    }
}

void test_challenge(void)
{
    test_receipts();
    test_conformance();
    test_extra_cases();
    test_roundtrip();
    test_credential_conformance();
}

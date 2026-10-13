#include "test.h"

#include "transponder/json.h"

/* Cases follow RFC 8259; the invalid ones are the classic JSONTestSuite traps. */

static int parses(const char *s)
{
    trp_json v;
    return trp_json_parse(s, strlen(s), &v) == TRP_OK;
}

static void test_validation(void)
{
    char deep[80];
    int i;

    CHECK(parses("{}"));
    CHECK(parses(" [ ] "));
    CHECK(parses("{\"a\":1,\"b\":[true,false,null],\"c\":{\"d\":\"e\"}}"));
    CHECK(parses("-0.5e+10"));
    CHECK(parses("\"caf\\u00e9 \\ud83d\\ude00 \\n \\/\""));
    CHECK(parses("\"caf\xc3\xa9\""));

    CHECK(!parses(""));
    CHECK(!parses("{\"a\":1,}"));
    CHECK(!parses("[1,]"));
    CHECK(!parses("{\"a\" 1}"));
    CHECK(!parses("{1:2}"));
    CHECK(!parses("01"));
    CHECK(!parses("1."));
    CHECK(!parses(".5"));
    CHECK(!parses("+1"));
    CHECK(!parses("\"\\x\""));
    CHECK(!parses("\"\\u12\""));
    CHECK(!parses("\"tab\there\""));
    CHECK(!parses("\"unterminated"));
    CHECK(!parses("{} x"));
    CHECK(!parses("tru"));
    CHECK(!parses("\"\xff\""));         /* not UTF-8 */
    CHECK(!parses("\"\xc0\xaf\""));     /* overlong */
    CHECK(!parses("\"\xed\xa0\x80\"")); /* encoded surrogate */
    CHECK(!parses("\"\xf4\x90\x80\x80\"")); /* past U+10FFFF */

    /* Nesting: 32 levels are accepted, 33 are not. */
    for (i = 0; i < 32; i++) deep[i] = '[';
    for (i = 0; i < 32; i++) deep[32 + i] = ']';
    deep[64] = '\0';
    CHECK(parses(deep));
    for (i = 0; i < 33; i++) deep[i] = '[';
    for (i = 0; i < 33; i++) deep[33 + i] = ']';
    deep[66] = '\0';
    CHECK(!parses(deep));
}

static void test_lookup(void)
{
    const char *doc = "{\"amount\":\"1000\",\"n\":42,\"flag\":true,\"a\\u0062\":\"escaped key\","
                      "\"list\":[1, \"x\", {\"k\":2}],\"name\":\"caf\\u00e9 \\ud83d\\ude00\"}";
    trp_json root, v, item;
    char s[64];
    size_t n, pos = 0;
    uint64_t u;
    int b, count = 0;

    CHECK(trp_json_parse(doc, strlen(doc), &root) == TRP_OK && root.type == TRP_JSON_OBJECT);

    CHECK(trp_json_get(&root, "amount", &v) == TRP_OK && v.type == TRP_JSON_STRING);
    CHECK(trp_json_get_string(&v, s, sizeof(s), &n) == TRP_OK && strcmp(s, "1000") == 0 && n == 4);
    CHECK(trp_json_get(&root, "n", &v) == TRP_OK && trp_json_get_uint64(&v, &u) == TRP_OK && u == 42);
    CHECK(trp_json_get(&root, "flag", &v) == TRP_OK && trp_json_get_bool(&v, &b) == TRP_OK && b == 1);
    CHECK(trp_json_get(&root, "ab", &v) == TRP_OK);
    CHECK(trp_json_get(&root, "name", &v) == TRP_OK);
    CHECK(trp_json_get_string(&v, s, sizeof(s), &n) == TRP_OK &&
          strcmp(s, "caf\xc3\xa9 \xf0\x9f\x98\x80") == 0);
    CHECK(trp_json_get(&root, "missing", &v) == TRP_ERR_NOT_FOUND);

    CHECK(trp_json_get(&root, "list", &v) == TRP_OK && v.type == TRP_JSON_ARRAY);
    while (trp_json_next(&v, &pos, &item) == TRP_OK) count++;
    CHECK(count == 3);
    CHECK(item.type == TRP_JSON_OBJECT);

    /* A repeated key is an error, not "first wins" or "last wins". */
    CHECK(trp_json_parse("{\"a\":1,\"a\":2}", 13, &root) == TRP_OK);
    CHECK(trp_json_get(&root, "a", &v) == TRP_ERR_INVALID);

    /* Strings: buffer limits and lone surrogates. */
    CHECK(trp_json_parse("\"abcdef\"", 8, &v) == TRP_OK);
    CHECK(trp_json_get_string(&v, s, 6, &n) == TRP_ERR_BUFFER);
    CHECK(trp_json_get_string(&v, s, 7, &n) == TRP_OK);
    CHECK(trp_json_parse("\"\\ud83d\"", 8, &v) == TRP_OK);
    CHECK(trp_json_get_string(&v, s, sizeof(s), &n) == TRP_ERR_INVALID);

    /* Integers. */
    CHECK(trp_json_parse("18446744073709551615", 20, &v) == TRP_OK);
    CHECK(trp_json_get_uint64(&v, &u) == TRP_OK && u == UINT64_MAX);
    CHECK(trp_json_parse("18446744073709551616", 20, &v) == TRP_OK);
    CHECK(trp_json_get_uint64(&v, &u) == TRP_ERR_INVALID);
    CHECK(trp_json_parse("-1", 2, &v) == TRP_OK && trp_json_get_uint64(&v, &u) == TRP_ERR_INVALID);
    CHECK(trp_json_parse("1.0", 3, &v) == TRP_OK && trp_json_get_uint64(&v, &u) == TRP_ERR_INVALID);
    CHECK(trp_json_parse("1e3", 3, &v) == TRP_OK && trp_json_get_uint64(&v, &u) == TRP_ERR_INVALID);
}

static void test_writer(void)
{
    char buf[128];
    trp_json_writer w;
    const char tricky[] = "q\"b\\n\n\001\xc3\xa9";

    /* Matches JSON.stringify: control characters as \u00xx, UTF-8 left as is. */
    trp_jw_init(&w, buf, sizeof(buf));
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "a");
    trp_jw_string(&w, "x", 1);
    trp_jw_key(&w, "b");
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "c");
    trp_jw_string(&w, tricky, sizeof(tricky) - 1);
    trp_jw_object_end(&w);
    trp_jw_key(&w, "d");
    trp_jw_raw(&w, "[1,2]", 5);
    trp_jw_object_end(&w);
    CHECK(trp_jw_finish(&w) == TRP_OK);
    CHECK(strcmp(buf, "{\"a\":\"x\",\"b\":{\"c\":\"q\\\"b\\\\n\\n\\u0001\xc3\xa9\"},\"d\":[1,2]}") == 0);

    /* "{}" plus the NUL needs 3 bytes. */
    trp_jw_init(&w, buf, 2);
    trp_jw_object_begin(&w);
    trp_jw_object_end(&w);
    CHECK(trp_jw_finish(&w) == TRP_ERR_BUFFER);
    trp_jw_init(&w, buf, 3);
    trp_jw_object_begin(&w);
    trp_jw_object_end(&w);
    CHECK(trp_jw_finish(&w) == TRP_OK && strcmp(buf, "{}") == 0);
}

void test_json(void)
{
    test_validation();
    test_lookup();
    test_writer();

    CHECK(trp_utf8_valid((const uint8_t *)"", 0));
    CHECK(trp_utf8_valid((const uint8_t *)"\xe2\x80\x94", 3));
    CHECK(!trp_utf8_valid((const uint8_t *)"\xe2\x80", 2));
    CHECK(!trp_utf8_valid((const uint8_t *)"\x80", 1));
}

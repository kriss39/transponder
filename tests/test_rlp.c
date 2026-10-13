#include "test.h"

#include "transponder/rlp.h"

/* Vectors from the Ethereum RLP specification (ethereum.org/developers/docs/data-structures-and-encoding/rlp). */

static void test_strings_and_ints(void)
{
    uint8_t buf[128];
    trp_rlp_writer w;
    const uint8_t zero_byte = 0x00, low_byte = 0x7f, high_byte = 0x80;
    const char *lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit";
    const uint8_t u256_one[32] = {[31] = 1};

    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    CHECK(w.err == TRP_OK);
    CHECK_HEX(buf, w.len, "83646f67");

    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_bytes(&w, NULL, 0);
    CHECK_HEX(buf, w.len, "80");

    /* A single byte below 0x80 is its own encoding; 0x80 itself is not. */
    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_bytes(&w, &zero_byte, 1);
    trp_rlp_bytes(&w, &low_byte, 1);
    trp_rlp_bytes(&w, &high_byte, 1);
    CHECK_HEX(buf, w.len, "007f8180");

    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_uint64(&w, 0);
    trp_rlp_uint64(&w, 15);
    trp_rlp_uint64(&w, 1024);
    trp_rlp_uint64(&w, 0xffffffffffffffffULL);
    CHECK_HEX(buf, w.len, "800f82040088ffffffffffffffff");

    /* A uint256 drops its leading zeros. */
    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_uint_be(&w, u256_one, sizeof(u256_one));
    CHECK_HEX(buf, w.len, "01");

    /* 56 bytes is the first length that needs the long form. */
    trp_rlp_init(&w, buf, sizeof(buf));
    trp_rlp_bytes(&w, (const uint8_t *)lorem, strlen(lorem));
    CHECK(w.len == 58 && buf[0] == 0xb8 && buf[1] == 0x38);
    CHECK(memcmp(buf + 2, lorem, 56) == 0);
}

static void test_lists(void)
{
    uint8_t buf[128];
    trp_rlp_writer w;
    size_t outer, a, b, c;

    trp_rlp_init(&w, buf, sizeof(buf));
    outer = trp_rlp_list_begin(&w);
    trp_rlp_bytes(&w, (const uint8_t *)"cat", 3);
    trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    trp_rlp_list_end(&w, outer);
    CHECK(w.err == TRP_OK);
    CHECK_HEX(buf, w.len, "c88363617483646f67");

    trp_rlp_init(&w, buf, sizeof(buf));
    outer = trp_rlp_list_begin(&w);
    trp_rlp_list_end(&w, outer);
    CHECK_HEX(buf, w.len, "c0");

    /* The set-theoretic representation of three: [ [], [[]], [ [], [[]] ] ] */
    trp_rlp_init(&w, buf, sizeof(buf));
    outer = trp_rlp_list_begin(&w);
    a = trp_rlp_list_begin(&w);
    trp_rlp_list_end(&w, a);
    a = trp_rlp_list_begin(&w);
    b = trp_rlp_list_begin(&w);
    trp_rlp_list_end(&w, b);
    trp_rlp_list_end(&w, a);
    a = trp_rlp_list_begin(&w);
    b = trp_rlp_list_begin(&w);
    trp_rlp_list_end(&w, b);
    b = trp_rlp_list_begin(&w);
    c = trp_rlp_list_begin(&w);
    trp_rlp_list_end(&w, c);
    trp_rlp_list_end(&w, b);
    trp_rlp_list_end(&w, a);
    trp_rlp_list_end(&w, outer);
    CHECK_HEX(buf, w.len, "c7c0c1c0c3c0c1c0");
}

static void test_long_list(void)
{
    uint8_t buf[128];
    trp_rlp_writer w;
    size_t list;
    int i;

    /* 20 x "dog" = 80 payload bytes: long-form header f850. */
    trp_rlp_init(&w, buf, sizeof(buf));
    list = trp_rlp_list_begin(&w);
    for (i = 0; i < 20; i++) trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    trp_rlp_list_end(&w, list);
    CHECK(w.err == TRP_OK && w.len == 82);
    CHECK(buf[0] == 0xf8 && buf[1] == 0x50 && buf[2] == 0x83);
}

static void test_overflow(void)
{
    uint8_t buf[5];
    trp_rlp_writer w;
    size_t list;

    /* After the first error, later writes are ignored. */
    trp_rlp_init(&w, buf, 4);
    trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    trp_rlp_bytes(&w, (const uint8_t *)"cat", 3);
    trp_rlp_uint64(&w, 1);
    CHECK(w.err == TRP_ERR_BUFFER);
    CHECK(w.len == 4);

    /* ["dog"] is 5 bytes: it fits exactly in 5 ... */
    trp_rlp_init(&w, buf, 5);
    list = trp_rlp_list_begin(&w);
    trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    trp_rlp_list_end(&w, list);
    CHECK(w.err == TRP_OK);
    CHECK_HEX(buf, w.len, "c483646f67");

    /* ... and fails in 4, where the item fits but the list header does not. */
    trp_rlp_init(&w, buf, 4);
    list = trp_rlp_list_begin(&w);
    trp_rlp_bytes(&w, (const uint8_t *)"dog", 3);
    trp_rlp_list_end(&w, list);
    CHECK(w.err == TRP_ERR_BUFFER);
}

void test_rlp(void)
{
    test_strings_and_ints();
    test_lists();
    test_long_list();
    test_overflow();
}

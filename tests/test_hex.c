#include "test.h"

void test_hex(void)
{
    const uint8_t bytes[] = {0x00, 0x0f, 0xa5, 0xff};
    uint8_t out[8];
    char str[16];
    size_t n = 0;

    CHECK(trp_hex_encode(bytes, sizeof(bytes), 1, str, sizeof(str)) == TRP_OK);
    CHECK(strcmp(str, "0x000fa5ff") == 0);
    CHECK(trp_hex_encode(bytes, sizeof(bytes), 0, str, sizeof(str)) == TRP_OK);
    CHECK(strcmp(str, "000fa5ff") == 0);

    /* Exactly enough room, then one byte short (the NUL counts). */
    CHECK(trp_hex_encode(bytes, sizeof(bytes), 1, str, 11) == TRP_OK);
    CHECK(trp_hex_encode(bytes, sizeof(bytes), 1, str, 10) == TRP_ERR_BUFFER);

    CHECK(trp_hex_decode("0x000FA5ff", 10, out, sizeof(out), &n) == TRP_OK);
    CHECK(n == 4 && memcmp(out, bytes, 4) == 0);
    CHECK(trp_hex_decode("000fa5ff", 8, out, sizeof(out), &n) == TRP_OK);
    CHECK(n == 4 && memcmp(out, bytes, 4) == 0);
    CHECK(trp_hex_decode("0x", 2, out, sizeof(out), &n) == TRP_OK && n == 0);

    CHECK(trp_hex_decode("abc", 3, out, sizeof(out), &n) == TRP_ERR_INVALID);
    CHECK(trp_hex_decode("zz", 2, out, sizeof(out), &n) == TRP_ERR_INVALID);
    CHECK(trp_hex_decode("000fa5ff", 8, out, 3, &n) == TRP_ERR_BUFFER);
}

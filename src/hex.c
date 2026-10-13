#include "transponder/hex.h"

static const char HEX_DIGITS[] = "0123456789abcdef";

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

trp_err_t trp_hex_encode(const uint8_t *data, size_t len, int prefix,
                         char *out, size_t out_cap)
{
    size_t need = (prefix ? 2 : 0) + len * 2 + 1;
    size_t i, o = 0;

    if (out_cap < need) return TRP_ERR_BUFFER;
    if (prefix) {
        out[o++] = '0';
        out[o++] = 'x';
    }
    for (i = 0; i < len; i++) {
        out[o++] = HEX_DIGITS[data[i] >> 4];
        out[o++] = HEX_DIGITS[data[i] & 0x0f];
    }
    out[o] = '\0';
    return TRP_OK;
}

trp_err_t trp_hex_decode(const char *hex, size_t len, uint8_t *out,
                         size_t out_cap, size_t *out_len)
{
    size_t i, n;

    if (len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        len -= 2;
    }
    if (len % 2 != 0) return TRP_ERR_INVALID;
    n = len / 2;
    if (n > out_cap) return TRP_ERR_BUFFER;
    for (i = 0; i < n; i++) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return TRP_ERR_INVALID;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len) *out_len = n;
    return TRP_OK;
}

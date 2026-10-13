#include "transponder/base64url.h"

static const char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int sextet(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

trp_err_t trp_base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_cap)
{
    size_t i, o = 0;

    if (out_cap < TRP_BASE64URL_ENCODED_LEN(len) + 1) return TRP_ERR_BUFFER;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
        out[o++] = ALPHABET[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
    } else if (len - i == 2) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
        out[o++] = ALPHABET[(v >> 18) & 63];
        out[o++] = ALPHABET[(v >> 12) & 63];
        out[o++] = ALPHABET[(v >> 6) & 63];
    }
    out[o] = '\0';
    return TRP_OK;
}

trp_err_t trp_base64url_decode(const char *in, size_t len, uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    size_t i, o = 0, full, rem;
    int pad = 0;

    while (len > 0 && in[len - 1] == '=' && pad < 2) {
        len--;
        pad++;
    }
    rem = len % 4;
    if (rem == 1) return TRP_ERR_INVALID;
    if (pad && (len + (size_t)pad) % 4 != 0) return TRP_ERR_INVALID;

    full = len - rem;
    if (out_cap < (full / 4) * 3 + (rem ? rem - 1 : 0)) return TRP_ERR_BUFFER;

    for (i = 0; i < full; i += 4) {
        int a = sextet(in[i]), b = sextet(in[i + 1]), c = sextet(in[i + 2]), d = sextet(in[i + 3]);
        uint32_t v;
        if ((a | b | c | d) < 0) return TRP_ERR_INVALID;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[o++] = (uint8_t)(v >> 16);
        out[o++] = (uint8_t)(v >> 8);
        out[o++] = (uint8_t)v;
    }
    if (rem) {
        int a = sextet(in[i]), b = sextet(in[i + 1]);
        int c = rem == 3 ? sextet(in[i + 2]) : 0;
        uint32_t v;
        if ((a | b | c) < 0) return TRP_ERR_INVALID;
        v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6);
        out[o++] = (uint8_t)(v >> 16);
        if (rem == 3) out[o++] = (uint8_t)(v >> 8);
    }
    if (out_len) *out_len = o;
    return TRP_OK;
}

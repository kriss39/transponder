#include "transponder/rlp.h"

#include <string.h>

void trp_rlp_init(trp_rlp_writer *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = TRP_OK;
}

static int reserve(trp_rlp_writer *w, size_t n)
{
    if (w->err != TRP_OK) return 0;
    if (w->cap - w->len < n) {
        w->err = TRP_ERR_BUFFER;
        return 0;
    }
    return 1;
}

/* Number of bytes needed to hold `n` big-endian, with no leading zeros. */
static size_t be_width(size_t n)
{
    size_t width = 0;
    while (n) {
        width++;
        n >>= 8;
    }
    return width;
}

static void put_be(uint8_t *dst, size_t n, size_t width)
{
    while (width--) {
        dst[width] = (uint8_t)(n & 0xff);
        n >>= 8;
    }
}

/* Header for a payload of `len` bytes: short form below 56, long form above. */
static size_t header(uint8_t *dst, uint8_t short_base, uint8_t long_base, size_t len)
{
    size_t width;

    if (len < 56) {
        dst[0] = (uint8_t)(short_base + len);
        return 1;
    }
    width = be_width(len);
    dst[0] = (uint8_t)(long_base + width);
    put_be(dst + 1, len, width);
    return 1 + width;
}

void trp_rlp_bytes(trp_rlp_writer *w, const uint8_t *data, size_t len)
{
    uint8_t hdr[1 + sizeof(size_t)];
    size_t hlen;

    if (len == 1 && data[0] < 0x80) {
        if (!reserve(w, 1)) return;
        w->buf[w->len++] = data[0];
        return;
    }
    hlen = header(hdr, 0x80, 0xb7, len);
    if (!reserve(w, hlen + len)) return;
    memcpy(w->buf + w->len, hdr, hlen);
    if (len) memcpy(w->buf + w->len + hlen, data, len);
    w->len += hlen + len;
}

void trp_rlp_uint_be(trp_rlp_writer *w, const uint8_t *be, size_t len)
{
    while (len && be[0] == 0) {
        be++;
        len--;
    }
    trp_rlp_bytes(w, be, len);
}

void trp_rlp_uint64(trp_rlp_writer *w, uint64_t value)
{
    uint8_t be[8];
    int i;

    for (i = 7; i >= 0; i--) {
        be[i] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
    trp_rlp_uint_be(w, be, sizeof(be));
}

void trp_rlp_raw(trp_rlp_writer *w, const uint8_t *data, size_t len)
{
    if (!reserve(w, len)) return;
    memcpy(w->buf + w->len, data, len);
    w->len += len;
}

size_t trp_rlp_list_begin(trp_rlp_writer *w)
{
    return w->len;
}

void trp_rlp_list_end(trp_rlp_writer *w, size_t marker)
{
    uint8_t hdr[1 + sizeof(size_t)];
    size_t payload, hlen;

    if (w->err != TRP_OK) return;
    if (marker > w->len) {
        w->err = TRP_ERR_INVALID;
        return;
    }
    payload = w->len - marker;
    hlen = header(hdr, 0xc0, 0xf7, payload);
    if (!reserve(w, hlen)) return;
    memmove(w->buf + marker + hlen, w->buf + marker, payload);
    memcpy(w->buf + marker, hdr, hlen);
    w->len += hlen;
}

#ifndef TRANSPONDER_RLP_H
#define TRANSPONDER_RLP_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RLP encoder that writes into a caller-owned buffer, with no allocation.
 *
 * Calls never fail individually: the first error is stored in `err` and
 * every later call becomes a no-op, so a whole structure can be written
 * and checked once at the end.
 *
 * Lists are written in place: trp_rlp_list_begin() returns a marker, the
 * items follow, and trp_rlp_list_end() shifts them right to insert the
 * list header. Nested lists work by keeping one marker per level.
 */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    trp_err_t err;
} trp_rlp_writer;

void trp_rlp_init(trp_rlp_writer *w, uint8_t *buf, size_t cap);

/* A byte string. */
void trp_rlp_bytes(trp_rlp_writer *w, const uint8_t *data, size_t len);

/* An unsigned integer: minimal big-endian bytes, zero encodes as 0x80. */
void trp_rlp_uint64(trp_rlp_writer *w, uint64_t value);

/* An unsigned big-endian integer of any width (e.g. a uint256). */
void trp_rlp_uint_be(trp_rlp_writer *w, const uint8_t *be, size_t len);

/* Bytes that are already RLP-encoded, copied as they are. */
void trp_rlp_raw(trp_rlp_writer *w, const uint8_t *data, size_t len);

size_t trp_rlp_list_begin(trp_rlp_writer *w);
void trp_rlp_list_end(trp_rlp_writer *w, size_t marker);

#ifdef __cplusplus
}
#endif

#endif

#ifndef TRANSPONDER_JSON_H
#define TRANSPONDER_JSON_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A small JSON reader and writer for the few objects MPP exchanges.
 *
 * The reader does not build a tree. trp_json_parse() validates a whole
 * document once; after that, values are views into the original text and
 * are looked up on demand. Input from a server is untrusted, so parsing
 * caps nesting depth, checks UTF-8, and lookups reject duplicate keys
 * rather than silently picking one.
 */

#define TRP_JSON_MAX_DEPTH 32

typedef enum {
    TRP_JSON_NULL,
    TRP_JSON_FALSE,
    TRP_JSON_TRUE,
    TRP_JSON_NUMBER,
    TRP_JSON_STRING,
    TRP_JSON_ARRAY,
    TRP_JSON_OBJECT
} trp_json_type;

/* A JSON value: its type and its raw text (strings include their quotes). */
typedef struct {
    trp_json_type type;
    const char *ptr;
    size_t len;
} trp_json;

/* Validate `len` bytes as exactly one JSON value, optionally surrounded by whitespace. */
trp_err_t trp_json_parse(const char *text, size_t len, trp_json *root);

/* Look up `key` in an object. TRP_ERR_NOT_FOUND if absent, TRP_ERR_INVALID if repeated. */
trp_err_t trp_json_get(const trp_json *object, const char *key, trp_json *out);

/* Iterate an array: start with *cursor = 0; returns TRP_ERR_NOT_FOUND after the last item. */
trp_err_t trp_json_next(const trp_json *array, size_t *cursor, trp_json *out);

/* Unescape a string value into `out` as NUL-terminated UTF-8. */
trp_err_t trp_json_get_string(const trp_json *value, char *out, size_t out_cap, size_t *out_len);

/* A non-negative integer with no fraction or exponent that fits in 64 bits. */
trp_err_t trp_json_get_uint64(const trp_json *value, uint64_t *out);

trp_err_t trp_json_get_bool(const trp_json *value, int *out);

/* Non-zero if `s` is well-formed UTF-8 (no overlongs, surrogates or code points past U+10FFFF). */
int trp_utf8_valid(const uint8_t *s, size_t len);

/*
 * Writer. Like the RLP writer, the first error sticks and later calls do
 * nothing. Output matches JavaScript's JSON.stringify for strings, which
 * is what the reference SDK (mppx) produces.
 */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    trp_err_t err;
    uint32_t has_items; /* bit n set: the object at depth n already has a member */
    unsigned depth;
} trp_json_writer;

void trp_jw_init(trp_json_writer *w, char *buf, size_t cap);
void trp_jw_object_begin(trp_json_writer *w);
void trp_jw_object_end(trp_json_writer *w);
void trp_jw_key(trp_json_writer *w, const char *key);
void trp_jw_string(trp_json_writer *w, const char *s, size_t len);
void trp_jw_raw(trp_json_writer *w, const char *json, size_t len);

/* NUL-terminate the output (the NUL is not counted in `len`). */
trp_err_t trp_jw_finish(trp_json_writer *w);

#ifdef __cplusplus
}
#endif

#endif

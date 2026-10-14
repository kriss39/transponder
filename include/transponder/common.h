#ifndef TRANSPONDER_COMMON_H
#define TRANSPONDER_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Every function that can fail returns one of these. Zero is success. */
typedef enum {
    TRP_OK = 0,
    TRP_ERR_BUFFER = -1,      /* caller's output buffer is too small */
    TRP_ERR_INVALID = -2,     /* malformed input */
    TRP_ERR_UNSUPPORTED = -3, /* valid input this library does not handle */
    TRP_ERR_CRYPTO = -4,      /* signer or hash backend failed */
    TRP_ERR_NOT_FOUND = -5,   /* a looked-up key or item is absent */
    TRP_ERR_DENIED = -6,      /* the spending policy or the approve callback refused to pay */
    TRP_ERR_PENDING = -7      /* not settled yet: a transaction may still land; ask again later */
} trp_err_t;

/* A borrowed, length-delimited string. `ptr` is NULL when absent. */
typedef struct {
    const char *ptr;
    size_t len;
} trp_str;

#ifdef __cplusplus
}
#endif

#endif

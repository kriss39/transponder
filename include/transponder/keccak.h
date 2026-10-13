#ifndef TRANSPONDER_KECCAK_H
#define TRANSPONDER_KECCAK_H

#include "transponder/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRP_KECCAK256_LEN 32

/* Streaming Keccak-256 (the Ethereum variant, not FIPS-202 SHA3-256). */
typedef struct {
    uint64_t state[25];
    size_t pos;
} trp_keccak_ctx;

void trp_keccak256_init(trp_keccak_ctx *ctx);
void trp_keccak256_update(trp_keccak_ctx *ctx, const uint8_t *data, size_t len);
void trp_keccak256_final(trp_keccak_ctx *ctx, uint8_t out[TRP_KECCAK256_LEN]);

void trp_keccak256(const uint8_t *data, size_t len, uint8_t out[TRP_KECCAK256_LEN]);

#ifdef __cplusplus
}
#endif

#endif

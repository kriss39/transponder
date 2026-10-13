#include "transponder/keccak.h"

#include <string.h>

#include "internal.h"

/* Keccak-f[1600] with a 1088-bit rate and 256-bit output. */
#define RATE 136
#define ROUNDS 24

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t ROUND_CONSTANTS[ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned ROTATIONS[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const unsigned PI_LANES[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

static void keccak_f1600(uint64_t st[25])
{
    uint64_t bc[5], t;
    int round, i, j;

    for (round = 0; round < ROUNDS; round++) {
        /* theta */
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) st[j + i] ^= t;
        }

        /* rho and pi */
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = (int)PI_LANES[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, ROTATIONS[i]);
            t = bc[0];
        }

        /* chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = st[j + i];
            for (i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* iota */
        st[0] ^= ROUND_CONSTANTS[round];
    }
}

/* Lanes are little-endian; working byte by byte keeps this endian-neutral. */
static void xor_byte(uint64_t st[25], size_t pos, uint8_t b)
{
    st[pos / 8] ^= (uint64_t)b << (8 * (pos % 8));
}

void trp_keccak256_init(trp_keccak_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void trp_keccak256_update(trp_keccak_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        xor_byte(ctx->state, ctx->pos++, data[i]);
        if (ctx->pos == RATE) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

static void finish(trp_keccak_ctx *ctx, uint8_t domain, uint8_t out[TRP_KECCAK256_LEN])
{
    size_t i;

    xor_byte(ctx->state, ctx->pos, domain);
    xor_byte(ctx->state, RATE - 1, 0x80);
    keccak_f1600(ctx->state);
    for (i = 0; i < TRP_KECCAK256_LEN; i++)
        out[i] = (uint8_t)(ctx->state[i / 8] >> (8 * (i % 8)));
    memset(ctx, 0, sizeof(*ctx));
}

void trp_keccak256_final(trp_keccak_ctx *ctx, uint8_t out[TRP_KECCAK256_LEN])
{
    finish(ctx, 0x01, out);
}

void trp__sha3_256_final(trp_keccak_ctx *ctx, uint8_t out[TRP_KECCAK256_LEN])
{
    finish(ctx, 0x06, out);
}

void trp_keccak256(const uint8_t *data, size_t len, uint8_t out[TRP_KECCAK256_LEN])
{
    trp_keccak_ctx ctx;

    trp_keccak256_init(&ctx);
    trp_keccak256_update(&ctx, data, len);
    trp_keccak256_final(&ctx, out);
}

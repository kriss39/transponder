#include "test.h"

#include "transponder/keccak.h"
#include "../src/internal.h"

static void pattern(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(i % 251);
}

void test_keccak(void)
{
    /* Known Keccak-256 values (the hashes Ethereum uses). */
    static const struct {
        const char *msg;
        const char *hash;
    } keccak_vectors[] = {
        {"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
        {"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
        {"The quick brown fox jumps over the lazy dog",
         "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
    };

    /*
     * SHA3-256 of bytes i % 251, from Python's hashlib. The lengths sit on
     * both sides of the 136-byte block boundary, so these exercise the
     * permutation and multi-block absorption against an independent
     * implementation.
     */
    static const struct {
        size_t len;
        const char *hash;
    } sha3_vectors[] = {
        {0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
        {1, "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"},
        {135, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"},
        {136, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"},
        {137, "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca"},
        {271, "0153fcdb6825d836b10835ccb3999dc1d8b68492f77e7e38afa31f8e244bd7af"},
        {272, "b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794"},
        {273, "4827800416bd25b01f53360454943ef688112eaee40422929a59af596a2c0be7"},
        {1000, "48e66a01861d0eadaacdb7a6ae7db6b9ac79242ecced4154a9fbb33c4e3cc571"},
    };

    uint8_t data[1000], digest[32], whole[32];
    trp_keccak_ctx ctx;
    size_t i, off;

    for (i = 0; i < sizeof(keccak_vectors) / sizeof(keccak_vectors[0]); i++) {
        trp_keccak256((const uint8_t *)keccak_vectors[i].msg,
                      strlen(keccak_vectors[i].msg), digest);
        CHECK_HEX(digest, 32, keccak_vectors[i].hash);
    }

    for (i = 0; i < sizeof(sha3_vectors) / sizeof(sha3_vectors[0]); i++) {
        pattern(data, sha3_vectors[i].len);
        trp_keccak256_init(&ctx);
        trp_keccak256_update(&ctx, data, sha3_vectors[i].len);
        trp__sha3_256_final(&ctx, digest);
        CHECK_HEX(digest, 32, sha3_vectors[i].hash);
    }

    /* Streaming in uneven chunks must match one-shot hashing. */
    pattern(data, sizeof(data));
    trp_keccak256(data, sizeof(data), whole);
    trp_keccak256_init(&ctx);
    for (off = 0; off < sizeof(data);) {
        size_t chunk = (off % 7) * 13 + 1;
        if (chunk > sizeof(data) - off) chunk = sizeof(data) - off;
        trp_keccak256_update(&ctx, data + off, chunk);
        off += chunk;
    }
    trp_keccak256_final(&ctx, digest);
    CHECK(memcmp(digest, whole, 32) == 0);
}

#include "trp_secure_enclave.h"

/* Implemented in trp_secure_enclave.swift. Return codes match trp_err_t. */
int trp__enclave_create(uint8_t *blob, long blob_cap, long *blob_len, uint8_t public_key[64]);
int trp__enclave_public_key(const uint8_t *blob, long blob_len, uint8_t public_key[64]);
int trp__enclave_sign(const uint8_t *blob, long blob_len, const uint8_t digest[32], uint8_t r[32],
                      uint8_t s[32]);

trp_err_t trp_enclave_key_create(trp_enclave_key *key)
{
    uint8_t unused[64];
    long len = 0;
    int err = trp__enclave_create(key->blob, (long)sizeof(key->blob), &len, unused);

    if (err != 0) return (trp_err_t)err;
    key->len = (size_t)len;
    return TRP_OK;
}

static trp_err_t sign_digest(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    trp_enclave_key *key = (trp_enclave_key *)ctx;
    return trp__enclave_sign(key->blob, (long)key->len, digest, r, s) == 0 ? TRP_OK : TRP_ERR_CRYPTO;
}

trp_err_t trp_enclave_signer_init(trp_signer *signer, trp_enclave_key *key)
{
    int err = trp__enclave_public_key(key->blob, (long)key->len, signer->public_key);

    if (err != 0) return (trp_err_t)err;
    signer->sign_digest = sign_digest;
    signer->ctx = key;
    signer->pre_hash = 1; /* CryptoKit signs SHA-256 of what it is given */
    return TRP_OK;
}

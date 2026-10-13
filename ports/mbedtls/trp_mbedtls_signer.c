#include "trp_mbedtls_signer.h"

#include <string.h>

/*
 * Deterministic ECDSA (RFC 6979) when available, so signatures are
 * reproducible in tests. The hash in the algorithm only picks the RFC 6979
 * nonce derivation; psa_sign_hash() signs the 32-byte digest as given.
 */
#ifdef PSA_WANT_ALG_DETERMINISTIC_ECDSA
#define SIGN_ALG PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256)
#else
#define SIGN_ALG PSA_ALG_ECDSA(PSA_ALG_SHA_256)
#endif

static trp_err_t sign_digest(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    trp_mbedtls_key *k = (trp_mbedtls_key *)ctx;
    uint8_t sig[64];
    size_t sig_len = 0;

    if (psa_sign_hash(k->key, SIGN_ALG, digest, 32, sig, sizeof(sig), &sig_len) != PSA_SUCCESS ||
        sig_len != sizeof(sig))
        return TRP_ERR_CRYPTO;
    memcpy(r, sig, 32);
    memcpy(s, sig + 32, 32);
    return TRP_OK;
}

static void attributes(psa_key_attributes_t *attr)
{
    *attr = psa_key_attributes_init();
    psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(attr, 256);
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(attr, SIGN_ALG);
}

/* PSA exports public keys as 0x04 || x || y. */
static trp_err_t finish(trp_signer *signer, trp_mbedtls_key *key)
{
    uint8_t pub[65];
    size_t len = 0;

    if (psa_export_public_key(key->key, pub, sizeof(pub), &len) != PSA_SUCCESS || len != 65 ||
        pub[0] != 0x04) {
        psa_destroy_key(key->key);
        return TRP_ERR_CRYPTO;
    }
    memcpy(signer->public_key, pub + 1, 64);
    signer->sign_digest = sign_digest;
    signer->ctx = key;
    return TRP_OK;
}

trp_err_t trp_mbedtls_signer_import(trp_signer *signer, trp_mbedtls_key *key,
                                    const uint8_t private_key[32])
{
    psa_key_attributes_t attr;

    if (psa_crypto_init() != PSA_SUCCESS) return TRP_ERR_CRYPTO;
    attributes(&attr);
    if (psa_import_key(&attr, private_key, 32, &key->key) != PSA_SUCCESS) return TRP_ERR_CRYPTO;
    return finish(signer, key);
}

trp_err_t trp_mbedtls_signer_generate(trp_signer *signer, trp_mbedtls_key *key)
{
    psa_key_attributes_t attr;

    if (psa_crypto_init() != PSA_SUCCESS) return TRP_ERR_CRYPTO;
    attributes(&attr);
    if (psa_generate_key(&attr, &key->key) != PSA_SUCCESS) return TRP_ERR_CRYPTO;
    return finish(signer, key);
}

void trp_mbedtls_signer_free(trp_mbedtls_key *key)
{
    psa_destroy_key(key->key);
}

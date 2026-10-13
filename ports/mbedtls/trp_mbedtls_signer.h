#ifndef TRANSPONDER_MBEDTLS_SIGNER_H
#define TRANSPONDER_MBEDTLS_SIGNER_H

/*
 * A software P-256 signer on the PSA Crypto API, which both mbedTLS 3.x
 * (ESP-IDF) and 4.x (Homebrew) provide. Use it on a computer, or on a
 * board without a secure element. The key lives in RAM, so prefer the
 * secure-element signer on devices that have one.
 */

#include <psa/crypto.h>

#include "transponder/charge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    psa_key_id_t key;
} trp_mbedtls_key;

/* Load a 32-byte P-256 private key and fill in `signer`. Calls psa_crypto_init(). */
trp_err_t trp_mbedtls_signer_import(trp_signer *signer, trp_mbedtls_key *key,
                                    const uint8_t private_key[32]);

/* Generate a new P-256 key from the PSA random generator and fill in `signer`. */
trp_err_t trp_mbedtls_signer_generate(trp_signer *signer, trp_mbedtls_key *key);

/* Destroy the key. */
void trp_mbedtls_signer_free(trp_mbedtls_key *key);

#ifdef __cplusplus
}
#endif

#endif

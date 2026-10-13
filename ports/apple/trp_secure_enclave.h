#ifndef TRANSPONDER_SECURE_ENCLAVE_H
#define TRANSPONDER_SECURE_ENCLAVE_H

/*
 * A signer backed by the Secure Enclave of an Apple-silicon Mac. The key is
 * created inside the enclave and cannot be exported; what the program keeps
 * is an encrypted blob that only this machine's enclave can use. Build the
 * Swift half (trp_secure_enclave.swift) together with trp_secure_enclave.c.
 */

#include "transponder/charge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRP_ENCLAVE_BLOB_MAX 512

typedef struct {
    uint8_t blob[TRP_ENCLAVE_BLOB_MAX];
    size_t len;
} trp_enclave_key;

/* Create a new key in the enclave. Save key->blob[0..len) to use it again. */
trp_err_t trp_enclave_key_create(trp_enclave_key *key);

/* Fill in `signer` for a key (new or loaded from a saved blob). */
trp_err_t trp_enclave_signer_init(trp_signer *signer, trp_enclave_key *key);

#ifdef __cplusplus
}
#endif

#endif

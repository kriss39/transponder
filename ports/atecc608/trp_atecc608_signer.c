#include "trp_atecc608_signer.h"

#include "cryptoauthlib.h"

/* The chip returns r || s; Transponder makes s low before it goes on chain. */
static trp_err_t sign_digest(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    const trp_atecc608_key *k = (const trp_atecc608_key *)ctx;
    uint8_t sig[ATCA_ECCP256_SIG_SIZE];
    size_t i;

    if (atcab_sign(k->slot, digest, sig) != ATCA_SUCCESS) return TRP_ERR_CRYPTO;
    for (i = 0; i < 32; i++) {
        r[i] = sig[i];
        s[i] = sig[32 + i];
    }
    return TRP_OK;
}

trp_err_t trp_atecc608_signer_init(trp_signer *signer, trp_atecc608_key *key, uint16_t slot)
{
    if (!signer || !key) return TRP_ERR_INVALID;
    key->slot = slot;
    /* x || y, 64 bytes, as Transponder wants it. */
    if (atcab_get_pubkey(slot, signer->public_key) != ATCA_SUCCESS) return TRP_ERR_CRYPTO;
    signer->sign_digest = sign_digest;
    signer->ctx = key;
    signer->pre_hash = 0; /* the chip signs the digest as given */
    return TRP_OK;
}

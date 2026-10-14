#ifndef TRANSPONDER_ATECC608_SIGNER_H
#define TRANSPONDER_ATECC608_SIGNER_H

/*
 * A P-256 signer on a Microchip ATECC608A/B secure element, through
 * cryptoauthlib (esp-cryptoauthlib on ESP-IDF). The private key is generated
 * inside the chip and never leaves it; the chip signs 32-byte digests.
 *
 * Call atcab_init() with your board's configuration first. On an
 * ESP32-WROOM-32SE the chip is inside the module, and esp-cryptoauthlib's
 * menuconfig sets its I2C pins, address and type (Trust&Go, TrustFLEX or
 * TrustCustom). The device key is usually in slot 0.
 */

#include "transponder/charge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t slot;
} trp_atecc608_key;

/* Read the public key of the P-256 key in `slot` and fill in `signer`. */
trp_err_t trp_atecc608_signer_init(trp_signer *signer, trp_atecc608_key *key, uint16_t slot);

#ifdef __cplusplus
}
#endif

#endif

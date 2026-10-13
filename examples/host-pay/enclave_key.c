/*
 * Create or inspect a device key held in this Mac's Secure Enclave.
 *
 *   ./build/enclave-key create .testnet/enclave.key   # new key; writes the blob and enclave.pub
 *   ./build/enclave-key show .testnet/enclave.key     # public key and access-key address
 *
 * The file holds an encrypted blob that only this Mac's enclave can use;
 * the private key itself cannot be exported.
 */

#include <stdio.h>
#include <string.h>

#include "transponder/hex.h"
#include "transponder/tempo.h"
#include "../../ports/apple/trp_secure_enclave.h"

static int show(const trp_signer *signer)
{
    char hex[2 * 64 + 3];
    uint8_t address[20];

    trp_hex_encode(signer->public_key, 64, 1, hex, sizeof(hex));
    printf("public key  %s\n", hex);
    trp_p256_address(signer->public_key, address);
    trp_hex_encode(address, 20, 1, hex, sizeof(hex));
    printf("key address %s\n", hex);
    return 0;
}

int main(int argc, char **argv)
{
    static trp_enclave_key key;
    trp_signer signer;
    FILE *f;

    if (argc != 3 || (strcmp(argv[1], "create") != 0 && strcmp(argv[1], "show") != 0)) {
        fprintf(stderr, "usage: %s create|show <blob file>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "create") == 0) {
        char pub_path[1024];
        char hex[2 * 64 + 3];

        if ((f = fopen(argv[2], "rb")) != NULL) {
            fclose(f);
            fprintf(stderr, "%s exists; refusing to replace a key\n", argv[2]);
            return 1;
        }
        if (trp_enclave_key_create(&key) != TRP_OK || trp_enclave_signer_init(&signer, &key) != TRP_OK) {
            fprintf(stderr, "could not create a Secure Enclave key\n");
            return 1;
        }
        if ((f = fopen(argv[2], "wb")) == NULL || fwrite(key.blob, 1, key.len, f) != key.len) {
            fprintf(stderr, "could not write %s\n", argv[2]);
            return 1;
        }
        fclose(f);
        /* The public key next to it, for tools/testnet/setup.mjs. */
        snprintf(pub_path, sizeof(pub_path), "%.*s.pub", (int)(strlen(argv[2]) - 4), argv[2]);
        if (strlen(argv[2]) > 4 && strcmp(argv[2] + strlen(argv[2]) - 4, ".key") == 0 &&
            (f = fopen(pub_path, "w")) != NULL) {
            trp_hex_encode(signer.public_key, 64, 1, hex, sizeof(hex));
            fprintf(f, "%s\n", hex);
            fclose(f);
        }
        printf("created a Secure Enclave key in %s\n", argv[2]);
        return show(&signer);
    }

    if ((f = fopen(argv[2], "rb")) == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[2]);
        return 1;
    }
    key.len = fread(key.blob, 1, sizeof(key.blob), f);
    fclose(f);
    if (trp_enclave_signer_init(&signer, &key) != TRP_OK) {
        fprintf(stderr, "this blob does not belong to this Mac's Secure Enclave\n");
        return 1;
    }
    return show(&signer);
}

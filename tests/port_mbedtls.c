/* Tests for ports/mbedtls: built and run by `make test-mbedtls`. */

#include "test.h"

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/tempo.h"
#include "../ports/mbedtls/trp_mbedtls_signer.h"
#include "tempo_vectors.h"

int trp_test_failures = 0;
int trp_test_checks = 0;

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    trp_hex_decode(hex, strlen(hex), out, cap, &n);
    return n;
}

static char scratch[4096];
static uint8_t work[8192];
static char header[8192];

/* The test key behind the vectors: 0x11 repeated 32 times. */
static const uint8_t TEST_PRIVATE_KEY[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
};

static void test_matches_ox(void)
{
    trp_signer signer;
    trp_mbedtls_key key;
    uint8_t want_pub[64], owner[20], token[20];
    trp_spend_policy policy;
    size_t i;

    CHECK(trp_mbedtls_signer_import(&signer, &key, TEST_PRIVATE_KEY) == TRP_OK);
    unhex(TV_PUBLIC_KEY, want_pub, sizeof(want_pub));
    CHECK(memcmp(signer.public_key, want_pub, 64) == 0);

    /* RFC 6979 makes the signature deterministic: after low-s it equals ox's. */
    for (i = 0; i < sizeof(TEMPO_VECTORS) / sizeof(TEMPO_VECTORS[0]); i++) {
        const tempo_vector *v = &TEMPO_VECTORS[i];
        uint8_t digest[32], r[32], s[32], want_r[32], want_s[32], got[130], want[130];

        unhex(v->keychain_digest, digest, 32);
        unhex(v->sig_r, want_r, 32);
        unhex(v->sig_s, want_s, 32);
        CHECK(signer.sign_digest(signer.ctx, digest, r, s) == TRP_OK);
        CHECK(trp_p256_signature(r, s, signer.public_key, 0, got) == TRP_OK);
        CHECK(trp_p256_signature(want_r, want_s, want_pub, 0, want) == TRP_OK);
        CHECK(memcmp(got, want, sizeof(got)) == 0);
    }

    /* The whole charge with the real signer gives the reference credential. */
    unhex(TV_OWNER, owner, 20);
    unhex(TV_TOKEN, token, 20);
    memset(&policy, 0, sizeof(policy));
    trp_u256_from_decimal("1000000", 7, policy.max_amount);
    for (i = 0; i < sizeof(CHARGE_VECTORS) / sizeof(CHARGE_VECTORS[0]); i++) {
        const charge_vector *v = &CHARGE_VECTORS[i];
        trp_charge_options opt;
        trp_challenge ch;

        memset(&opt, 0, sizeof(opt));
        opt.policy = &policy;
        opt.owner = owner;
        opt.signer = &signer;
        opt.now = v->now;
        opt.valid_after = v->valid_after;
        opt.gas_limit = v->gas;
        opt.max_fee_per_gas = v->max_fee_per_gas;
        opt.max_priority_fee_per_gas = v->max_priority_fee_per_gas;
        opt.fee_token = v->has_fee_token ? token : NULL;
        if (v->client_id) {
            opt.client_id.ptr = v->client_id;
            opt.client_id.len = strlen(v->client_id);
        }
        CHECK(trp_challenge_parse(v->wire, strlen(v->wire), &ch, scratch, sizeof(scratch)) == TRP_OK);
        CHECK(trp_tempo_charge(&ch, &opt, header, sizeof(header), work, sizeof(work), NULL) == TRP_OK);
        CHECK(strcmp(header, v->credential) == 0);
    }
    trp_mbedtls_signer_free(&key);
}

static void test_generated_key(void)
{
    trp_signer signer;
    trp_mbedtls_key key;
    uint8_t digest[32] = {1, 2, 3}, r[32], s[32], sig[64], pub[65];
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t verify_key;

    CHECK(trp_mbedtls_signer_generate(&signer, &key) == TRP_OK);
    CHECK(signer.sign_digest(signer.ctx, digest, r, s) == TRP_OK);

    /* Verify with the exported public key through a separate PSA key. */
    pub[0] = 0x04;
    memcpy(pub + 1, signer.public_key, 64);
    memcpy(sig, r, 32);
    memcpy(sig + 32, s, 32);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA_ANY);
    CHECK(psa_import_key(&attr, pub, sizeof(pub), &verify_key) == PSA_SUCCESS);
    CHECK(psa_verify_hash(verify_key, PSA_ALG_ECDSA_ANY, digest, 32, sig, 64) == PSA_SUCCESS);
    digest[0] ^= 1;
    CHECK(psa_verify_hash(verify_key, PSA_ALG_ECDSA_ANY, digest, 32, sig, 64) != PSA_SUCCESS);
    psa_destroy_key(verify_key);
    trp_mbedtls_signer_free(&key);
}

int main(void)
{
    test_matches_ox();
    test_generated_key();
    printf("%s mbedtls signer\n\n%d checks, %d failed\n", trp_test_failures ? "FAIL" : "ok  ",
           trp_test_checks, trp_test_failures);
    return trp_test_failures == 0 ? 0 : 1;
}

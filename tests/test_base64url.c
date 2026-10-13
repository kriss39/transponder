#include "test.h"

#include "transponder/base64url.h"
#include "transponder/json.h"
#include "conformance_vectors.h"

void test_base64url(void)
{
    char enc[128];
    uint8_t dec[128];
    size_t i, n;

    /* tempoxyz/mpp-tools vectors. A string that is not valid UTF-8 is a
     * rejection at the string layer, so check that separately. */
    for (i = 0; i < sizeof(B64_VECTORS) / sizeof(B64_VECTORS[0]); i++) {
        const b64_vector *v = &B64_VECTORS[i];
        trp_err_t err = trp_base64url_decode(v->encoded, strlen(v->encoded), dec, sizeof(dec), &n);
        if (v->ok) {
            CHECK(err == TRP_OK);
            CHECK(n == strlen(v->decoded) && memcmp(dec, v->decoded, n) == 0);
            CHECK(trp_base64url_encode((const uint8_t *)v->decoded, strlen(v->decoded), enc,
                                       sizeof(enc)) == TRP_OK);
            CHECK(strcmp(enc, v->encoded) == 0);
        } else {
            CHECK(err != TRP_OK || !trp_utf8_valid(dec, n));
        }
    }

    /* Padding is tolerated on input; '+' and '/' (standard base64) are not. */
    CHECK(trp_base64url_decode("YQ==", 4, dec, sizeof(dec), &n) == TRP_OK && n == 1 && dec[0] == 'a');
    CHECK(trp_base64url_decode("YWI=", 4, dec, sizeof(dec), &n) == TRP_OK && n == 2);
    CHECK(trp_base64url_decode("YQ=", 3, dec, sizeof(dec), &n) == TRP_ERR_INVALID);
    CHECK(trp_base64url_decode("Pj4+", 4, dec, sizeof(dec), &n) == TRP_ERR_INVALID);
    CHECK(trp_base64url_decode("Pz8/", 4, dec, sizeof(dec), &n) == TRP_ERR_INVALID);
    CHECK(trp_base64url_decode("YWJjZ", 5, dec, sizeof(dec), &n) == TRP_ERR_INVALID);

    /* Buffer limits. */
    CHECK(trp_base64url_decode("YWJj", 4, dec, 2, &n) == TRP_ERR_BUFFER);
    CHECK(trp_base64url_encode((const uint8_t *)"abc", 3, enc, 4) == TRP_ERR_BUFFER);
    CHECK(trp_base64url_encode((const uint8_t *)"abc", 3, enc, 5) == TRP_OK);
    CHECK(TRP_BASE64URL_ENCODED_LEN(0) == 0 && TRP_BASE64URL_ENCODED_LEN(1) == 2 &&
          TRP_BASE64URL_ENCODED_LEN(2) == 3 && TRP_BASE64URL_ENCODED_LEN(3) == 4);
}

/*
 * Pay for an HTTP resource over MPP from a computer, the way a device would.
 *
 *   set -a; . .testnet/device.env; set +a
 *   ./build/pay http://127.0.0.1:8402/reading
 *
 * GET the URL; on 402, pick the Tempo charge challenge, sign the payment
 * with the device key (software, through mbedTLS here; a secure element on
 * a board), and retry with the credential. Configuration comes from the
 * environment, as written by tools/testnet/setup.mjs:
 *
 *   TRP_OWNER         account the device key pays for (0x...)
 *   TRP_DEVICE_KEY    the device's P-256 private key (testnet only)
 *   TRP_CHAIN_ID      the only chain this device will pay on
 *   TRP_MAX_AMOUNT    most it pays per request, in base units (default 100000 = 0.10)
 *   TRP_GAS, TRP_MAX_FEE, TRP_PRIORITY_FEE   gas limit and fee caps
 *   TRP_FEE_TOKEN     token that pays the network fee
 *   TRP_ENCLAVE_KEY   optional: a Secure Enclave key blob (build with `make pay-enclave`);
 *                     when set, it signs instead of TRP_DEVICE_KEY
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/hex.h"
#include "transponder/receipt.h"
#include "../../ports/mbedtls/trp_mbedtls_signer.h"
#ifdef TRP_WITH_ENCLAVE
#include "../../ports/apple/trp_secure_enclave.h"
#endif

typedef struct {
    char challenge[8192]; /* WWW-Authenticate values, comma-joined */
    size_t challenge_len;
    char receipt[2048];
    char body[4096];
    size_t body_len;
} exchange;

static size_t on_header(char *line, size_t size, size_t n, void *userdata)
{
    exchange *ex = (exchange *)userdata;
    size_t len = size * n, vlen;
    const char *value;

    if (len > 17 && strncasecmp(line, "www-authenticate:", 17) == 0) {
        value = line + 17;
        vlen = len - 17;
        while (vlen && (*value == ' ' || *value == '\t')) value++, vlen--;
        while (vlen && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n')) vlen--;
        if (ex->challenge_len + vlen + 3 < sizeof(ex->challenge)) {
            if (ex->challenge_len) {
                memcpy(ex->challenge + ex->challenge_len, ", ", 2);
                ex->challenge_len += 2;
            }
            memcpy(ex->challenge + ex->challenge_len, value, vlen);
            ex->challenge_len += vlen;
            ex->challenge[ex->challenge_len] = '\0';
        }
    } else if (len > 16 && strncasecmp(line, "payment-receipt:", 16) == 0) {
        vlen = len - 16;
        if (vlen >= sizeof(ex->receipt)) vlen = sizeof(ex->receipt) - 1;
        memcpy(ex->receipt, line + 16, vlen);
        ex->receipt[vlen] = '\0';
    }
    return len;
}

static size_t on_body(char *data, size_t size, size_t n, void *userdata)
{
    exchange *ex = (exchange *)userdata;
    size_t len = size * n, room = sizeof(ex->body) - 1 - ex->body_len;
    if (len < room) room = len;
    memcpy(ex->body + ex->body_len, data, room);
    ex->body_len += room;
    ex->body[ex->body_len] = '\0';
    return len;
}

static long get(const char *url, const char *auth_header, exchange *ex)
{
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    long status = 0;

    memset(ex, 0, sizeof(*ex));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, ex);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ex);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    if (auth_header) {
        headers = curl_slist_append(headers, auth_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    if (curl_easy_perform(curl) == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}

static const char *env(const char *name)
{
    const char *v = getenv(name);
    if (!v || !*v) {
        fprintf(stderr, "missing %s (source .testnet/device.env)\n", name);
        exit(2);
    }
    return v;
}

static void hex_env(const char *name, uint8_t *out, size_t n)
{
    const char *v = env(name);
    size_t got = 0;
    if (trp_hex_decode(v, strlen(v), out, n, &got) != TRP_OK || got != n) {
        fprintf(stderr, "%s must be %zu bytes of hex\n", name, n);
        exit(2);
    }
}

int main(int argc, char **argv)
{
    static exchange ex;
    static char scratch[2 * sizeof(ex.challenge) + 16];
    static uint8_t work[4096];
    static char credential[4096], header_line[4200];
    uint8_t owner[20], device_key[32], fee_token[20];
    trp_signer signer;
    trp_mbedtls_key key = {0};
    trp_charge_options opt;
    trp_charge_result result;
    trp_spend_policy policy;
    const char *max_amount;
    uint64_t chain_id;
    trp_challenge ch;
    trp_err_t err;
    long status;
    uint64_t now;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <url>\n", argv[0]);
        return 2;
    }
    hex_env("TRP_OWNER", owner, sizeof(owner));
    hex_env("TRP_FEE_TOKEN", fee_token, sizeof(fee_token));
    curl_global_init(CURL_GLOBAL_DEFAULT);

    status = get(argv[1], NULL, &ex);
    printf("GET %s -> %ld\n", argv[1], status);
    if (status != 402) {
        printf("%s\n", ex.body);
        return status == 200 ? 0 : 1;
    }

    err = trp_challenge_select(ex.challenge, ex.challenge_len, "tempo", "charge", &ch, scratch,
                               sizeof(scratch));
    if (err != TRP_OK) {
        fprintf(stderr, "no Tempo charge challenge (%d): %s\n", (int)err, ex.challenge);
        return 1;
    }
    printf("challenge %s from %s: %s\n", ch.id.ptr, ch.realm.ptr,
           ch.description.ptr ? ch.description.ptr : "");

#ifdef TRP_WITH_ENCLAVE
    if (getenv("TRP_ENCLAVE_KEY") && *getenv("TRP_ENCLAVE_KEY")) {
        static trp_enclave_key enclave;
        FILE *f = fopen(getenv("TRP_ENCLAVE_KEY"), "rb");
        if (!f) {
            fprintf(stderr, "cannot read TRP_ENCLAVE_KEY\n");
            return 1;
        }
        enclave.len = fread(enclave.blob, 1, sizeof(enclave.blob), f);
        fclose(f);
        if (trp_enclave_signer_init(&signer, &enclave) != TRP_OK) {
            fprintf(stderr, "could not load the Secure Enclave key\n");
            return 1;
        }
        printf("signing with the Secure Enclave\n");
        key.key = 0;
    } else
#endif
    {
        hex_env("TRP_DEVICE_KEY", device_key, sizeof(device_key));
        if (trp_mbedtls_signer_import(&signer, &key, device_key) != TRP_OK) {
            fprintf(stderr, "could not load the device key\n");
            return 1;
        }
        printf("signing with a software key (mbedTLS)\n");
    }
    memset(&opt, 0, sizeof(opt));
    now = (uint64_t)time(NULL);
    opt.owner = owner;
    opt.signer = &signer;
    opt.now = now;
    opt.valid_after = now - 60 - (uint64_t)arc4random_uniform(86400); /* a random past second */
    /* The device's own limits: the server only asks, this decides. */
    memset(&policy, 0, sizeof(policy));
    max_amount = getenv("TRP_MAX_AMOUNT") ? getenv("TRP_MAX_AMOUNT") : "100000";
    if (trp_u256_from_decimal(max_amount, strlen(max_amount), policy.max_amount) != TRP_OK) {
        fprintf(stderr, "TRP_MAX_AMOUNT must be a decimal number of base units\n");
        return 2;
    }
    chain_id = strtoull(env("TRP_CHAIN_ID"), NULL, 10);
    policy.chain_ids = &chain_id;
    policy.chain_id_count = 1;
    opt.policy = &policy;
    opt.gas_limit = strtoull(env("TRP_GAS"), NULL, 10);
    opt.max_fee_per_gas = strtoull(env("TRP_MAX_FEE"), NULL, 10);
    opt.max_priority_fee_per_gas = strtoull(env("TRP_PRIORITY_FEE"), NULL, 10);
    opt.fee_token = fee_token;
    opt.client_id.ptr = "transponder";
    opt.client_id.len = 11;

    err = trp_tempo_charge(&ch, &opt, credential, sizeof(credential), work, sizeof(work), &result);
    if (err == TRP_ERR_DENIED) {
        fprintf(stderr, "refused: the challenge is outside this device's spending policy\n");
        return 1;
    }
    if (key.key) trp_mbedtls_signer_free(&key);
    if (err != TRP_OK) {
        fprintf(stderr, "could not build the payment (%d)\n", (int)err);
        return 1;
    }
    snprintf(header_line, sizeof(header_line), "%s: %s", trp_challenge_credential_header(&ch),
             credential);

    status = get(argv[1], header_line, &ex);
    printf("GET %s with payment -> %ld\n", argv[1], status);
    printf("%s\n", ex.body);
    if (ex.receipt[0]) {
        static char receipt_scratch[2 * sizeof(ex.receipt) + 16];
        trp_receipt receipt;
        const char *value = ex.receipt;
        while (*value == ' ') value++;
        printf("Payment-Receipt:%s\n", ex.receipt);
        if (trp_receipt_parse(value, strlen(value), &receipt, receipt_scratch, sizeof(receipt_scratch)) == TRP_OK)
            printf("receipt %s: %.*s\n",
                   trp_receipt_verify(&receipt, "tempo", result.request.fee_payer ? NULL : result.tx_hash) == TRP_OK
                       ? "matches the transaction this device signed"
                       : "does NOT match",
                   (int)receipt.reference.len, receipt.reference.ptr);
    }
    curl_global_cleanup();
    return status == 200 ? 0 : 1;
}

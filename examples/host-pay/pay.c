/*
 * Pay for an HTTP resource over MPP from a computer, the way a device would.
 *
 *   set -a; . .testnet/device.env; set +a
 *   ./build/pay http://127.0.0.1:8402/reading
 *   ./build/pay --session 5 http://127.0.0.1:8402/stream
 *
 * GET the URL; on 402, pick the Tempo charge challenge, sign the payment
 * with the device key (software, through mbedTLS here; a secure element on
 * a board), and retry with the credential.
 *
 * With --session N, pick the Tempo session challenge instead: open a channel
 * (one deposit on chain), then pay for N requests in all with vouchers,
 * topping the channel up when the deposit runs out, and close it.
 *
 * Configuration comes from the environment, as written by
 * tools/testnet/setup.mjs:
 *
 *   TRP_OWNER         account the device key pays for (0x...)
 *   TRP_DEVICE_KEY    the device's P-256 private key (testnet only)
 *   TRP_CHAIN_ID      the only chain this device will pay on
 *   TRP_MAX_AMOUNT    most it pays per request, in base units (default 100000 = 0.10)
 *   TRP_GAS, TRP_MAX_FEE, TRP_PRIORITY_FEE   gas limit and fee caps
 *   TRP_FEE_TOKEN     token that pays the network fee
 *   TRP_ENCLAVE_KEY   optional: a Secure Enclave key blob (build with `make pay-enclave`);
 *                     when set, it signs instead of TRP_DEVICE_KEY
 *   TRP_SESSION_KEY, TRP_SESSION_ENCLAVE_KEY, TRP_SESSION_GAS
 *                     the same for --session: a key that may only open and
 *                     top up channels, and the gas for those transactions
 *   TRP_SESSION_DEPOSIT   optional: deposit in base units (default: the
 *                     server's suggestedDeposit, else N times the price)
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
#include "transponder/session.h"
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

/* Load the signer: a Secure Enclave key when `enclave_var` is set, else a software key. */
static int load_signer(const char *key_var, const char *enclave_var, trp_signer *signer, trp_mbedtls_key *key)
{
    uint8_t device_key[32];

#ifdef TRP_WITH_ENCLAVE
    if (getenv(enclave_var) && *getenv(enclave_var)) {
        static trp_enclave_key enclave;
        FILE *f = fopen(getenv(enclave_var), "rb");
        if (!f) {
            fprintf(stderr, "cannot read %s\n", enclave_var);
            return -1;
        }
        enclave.len = fread(enclave.blob, 1, sizeof(enclave.blob), f);
        fclose(f);
        if (trp_enclave_signer_init(signer, &enclave) != TRP_OK) {
            fprintf(stderr, "could not load the Secure Enclave key\n");
            return -1;
        }
        printf("signing with the Secure Enclave\n");
        key->key = 0;
        return 0;
    }
#else
    (void)enclave_var;
#endif
    hex_env(key_var, device_key, sizeof(device_key));
    if (trp_mbedtls_signer_import(signer, key, device_key) != TRP_OK) {
        fprintf(stderr, "could not load the device key\n");
        return -1;
    }
    memset(device_key, 0, sizeof(device_key));
    printf("signing with a software key (mbedTLS)\n");
    return 0;
}

/* Pick the challenge for `intent` from the last response. The challenge is
 * copied out of the exchange, which the next request overwrites. */
static trp_err_t select_challenge(const exchange *ex, const char *intent, trp_challenge *ch)
{
    static char wire[sizeof(ex->challenge)];
    static char scratch[2 * sizeof(ex->challenge) + 16];

    memcpy(wire, ex->challenge, ex->challenge_len + 1);
    return trp_challenge_select(wire, ex->challenge_len, "tempo", intent, ch, scratch, sizeof(scratch));
}

static long send_credential(const char *url, const trp_challenge *ch, const char *credential, exchange *ex)
{
    static char line[16384 + 64];
    snprintf(line, sizeof(line), "%s: %s", trp_challenge_credential_header(ch), credential);
    return get(url, line, ex);
}

static void u256_from_u64(uint64_t v, uint8_t out[32])
{
    char dec[24];
    snprintf(dec, sizeof(dec), "%llu", (unsigned long long)v);
    trp_u256_from_decimal(dec, strlen(dec), out);
}

static int u64_from_u256(const uint8_t v[32], uint64_t *out)
{
    int i;
    for (i = 0; i < 24; i++)
        if (v[i]) return -1;
    *out = 0;
    for (i = 24; i < 32; i++) *out = (*out << 8) | v[i];
    return 0;
}

static void print_receipt(const exchange *ex)
{
    if (ex->receipt[0]) printf("  Payment-Receipt:%s\n", ex->receipt);
}

/* Open a channel, pay for `n` requests in all, top up as needed, close. */
static int run_session(const char *url, int n, const trp_charge_options *opt, exchange *ex)
{
    static uint8_t work[8192];
    static char credential[16384];
    trp_challenge ch;
    trp_session_request r;
    trp_session s;
    uint8_t deposit[32], salt[32], amount[32];
    uint64_t price, initial, deposited;
    const char *env_deposit = getenv("TRP_SESSION_DEPOSIT");
    trp_err_t err;
    long status;
    int i;

    if ((err = select_challenge(ex, "session", &ch)) != TRP_OK) {
        fprintf(stderr, "no Tempo session challenge (%d): %s\n", (int)err, ex->challenge);
        return 1;
    }
    if ((err = trp_session_request_parse(&ch, &r)) != TRP_OK || u64_from_u256(r.price, &price) != 0 || price == 0) {
        fprintf(stderr, "unsupported session challenge (%d)\n", (int)err);
        return 1;
    }
    if (env_deposit) {
        if (trp_u256_from_decimal(env_deposit, strlen(env_deposit), deposit) != TRP_OK) return 2;
    } else if (r.has_suggested_deposit) {
        memcpy(deposit, r.suggested_deposit, 32);
    } else {
        u256_from_u64(price * (uint64_t)n, deposit);
    }
    if (u64_from_u256(deposit, &initial) != 0) return 2;
    printf("session: %llu per request, opening a channel with %llu\n", (unsigned long long)price,
           (unsigned long long)initial);

    arc4random_buf(salt, sizeof(salt));
    err = trp_session_open(&ch, opt, deposit, salt, &s, credential, sizeof(credential), work, sizeof(work));
    if (err == TRP_ERR_DENIED) {
        fprintf(stderr, "refused: the deposit is outside this device's spending policy\n");
        return 1;
    }
    if (err != TRP_OK) {
        fprintf(stderr, "could not open the channel (%d)\n", (int)err);
        return 1;
    }
    printf("channel 0x");
    for (i = 0; i < 32; i++) printf("%02x", s.channel_id[i]);
    printf("\n");
    status = send_credential(url, &ch, credential, ex);
    printf("request 1 (open) -> %ld %s\n", status, ex->body);
    print_receipt(ex);
    if (status != 200) return 1;
    deposited = initial;

    for (i = 2; i <= n; i++) {
        uint64_t total = price * (uint64_t)i;
        int attempt;

        if (total > deposited) {
            u256_from_u64(initial, amount);
            err = trp_session_top_up(&s, &ch, opt, amount, credential, sizeof(credential), work, sizeof(work));
            if (err != TRP_OK) {
                fprintf(stderr, "could not top up (%d)\n", (int)err);
                return 1;
            }
            status = send_credential(url, &ch, credential, ex);
            printf("top up +%llu -> %ld\n", (unsigned long long)initial, status);
            if (status != 200 && status != 204) {
                printf("%s\n", ex->body);
                return 1;
            }
            deposited += initial;
        }
        u256_from_u64(total, amount);
        for (attempt = 0; attempt < 2; attempt++) {
            err = trp_session_voucher(&s, &ch, opt->signer, amount, credential, sizeof(credential), work,
                                      sizeof(work));
            if (err != TRP_OK) {
                fprintf(stderr, "could not sign the voucher (%d)\n", (int)err);
                return 1;
            }
            status = send_credential(url, &ch, credential, ex);
            /* A stale challenge earns a fresh one; sign again against it. */
            if (status != 402 || select_challenge(ex, "session", &ch) != TRP_OK) break;
        }
        printf("request %d (voucher for %llu) -> %ld %s\n", i, (unsigned long long)total, status, ex->body);
        if (status != 200) return 1;
    }

    err = trp_session_close(&s, &ch, opt->signer, credential, sizeof(credential), work, sizeof(work));
    if (err != TRP_OK) {
        fprintf(stderr, "could not close (%d)\n", (int)err);
        return 1;
    }
    status = send_credential(url, &ch, credential, ex);
    printf("close at %llu -> %ld %s\n", (unsigned long long)(price * (uint64_t)n), status, ex->body);
    print_receipt(ex);
    return status == 200 || status == 204 ? 0 : 1;
}

int main(int argc, char **argv)
{
    static exchange ex;
    static uint8_t work[4096];
    static char credential[4096];
    uint8_t owner[20], fee_token[20];
    trp_signer signer;
    trp_mbedtls_key key = {0};
    trp_charge_options opt;
    trp_charge_result result;
    trp_spend_policy policy;
    const char *max_amount, *url;
    uint64_t chain_id;
    trp_challenge ch;
    trp_err_t err;
    long status;
    uint64_t now;
    int sessions = 0, rc;

    if (argc == 4 && strcmp(argv[1], "--session") == 0 && atoi(argv[2]) > 0) {
        sessions = atoi(argv[2]);
        url = argv[3];
    } else if (argc == 2) {
        url = argv[1];
    } else {
        fprintf(stderr, "usage: %s [--session <requests>] <url>\n", argv[0]);
        return 2;
    }
    hex_env("TRP_OWNER", owner, sizeof(owner));
    hex_env("TRP_FEE_TOKEN", fee_token, sizeof(fee_token));
    curl_global_init(CURL_GLOBAL_DEFAULT);

    status = get(url, NULL, &ex);
    printf("GET %s -> %ld\n", url, status);
    if (status != 402) {
        printf("%s\n", ex.body);
        return status == 200 ? 0 : 1;
    }

    if (sessions ? load_signer("TRP_SESSION_KEY", "TRP_SESSION_ENCLAVE_KEY", &signer, &key)
                 : load_signer("TRP_DEVICE_KEY", "TRP_ENCLAVE_KEY", &signer, &key))
        return 1;
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
    opt.gas_limit = strtoull(env(sessions ? "TRP_SESSION_GAS" : "TRP_GAS"), NULL, 10);
    opt.max_fee_per_gas = strtoull(env("TRP_MAX_FEE"), NULL, 10);
    opt.max_priority_fee_per_gas = strtoull(env("TRP_PRIORITY_FEE"), NULL, 10);
    opt.fee_token = fee_token;
    opt.client_id.ptr = "transponder";
    opt.client_id.len = 11;

    if (sessions) {
        rc = run_session(url, sessions, &opt, &ex);
        if (key.key) trp_mbedtls_signer_free(&key);
        curl_global_cleanup();
        return rc;
    }

    if ((err = select_challenge(&ex, "charge", &ch)) != TRP_OK) {
        fprintf(stderr, "no Tempo charge challenge (%d): %s\n", (int)err, ex.challenge);
        return 1;
    }
    printf("challenge %s from %s: %s\n", ch.id.ptr, ch.realm.ptr,
           ch.description.ptr ? ch.description.ptr : "");
    err = trp_tempo_charge(&ch, &opt, credential, sizeof(credential), work, sizeof(work), &result);
    if (key.key) trp_mbedtls_signer_free(&key);
    if (err == TRP_ERR_DENIED) {
        fprintf(stderr, "refused: the challenge is outside this device's spending policy\n");
        return 1;
    }
    if (err != TRP_OK) {
        fprintf(stderr, "could not build the payment (%d)\n", (int)err);
        return 1;
    }

    status = send_credential(url, &ch, credential, &ex);
    printf("GET %s with payment -> %ld\n", url, status);
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

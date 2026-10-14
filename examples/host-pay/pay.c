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
 *   ./build/pay --session 3 --state channel.bin http://127.0.0.1:8402/stream
 *
 * With --state FILE, the session survives a restart, as on a device that
 * keeps it in flash: it is saved before every credential goes out, read back
 * and checked against the chain on the next run, which continues the same
 * channel and leaves it open. --session 0 --state FILE closes it.
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
 *   TRP_RPC_URL       optional, for --state: where to read the channel
 *                     (default https://rpc.moderato.tempo.xyz)
 */

#define _DEFAULT_SOURCE /* arc4random on glibc */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

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

/* POST a JSON-RPC request; the answer lands in ex->body. */
static long post_json(const char *url, const char *body, exchange *ex)
{
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    long status = 0;

    memset(ex, 0, sizeof(*ex));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ex);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    if (curl_easy_perform(curl) == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}

/* Write the session to `path` before its credential goes out, as a device writes it to flash. */
static int save_state(const char *path, const trp_session *s)
{
    uint8_t state[TRP_SESSION_STATE_LEN];
    FILE *f;

    if (!path) return 0;
    trp_session_save(s, state);
    if (!(f = fopen(path, "wb")) || fwrite(state, 1, sizeof(state), f) != sizeof(state) || fclose(f) != 0) {
        fprintf(stderr, "could not save the session to %s\n", path);
        return -1;
    }
    return 0;
}

/*
 * Restore the session saved in `path` and check it against the chain.
 * 1: a usable channel; 0: none (no file, or the channel is gone); -1: error.
 */
static int restore_state(const char *path, trp_session *s)
{
    static exchange rpc;
    uint8_t state[TRP_SESSION_STATE_LEN + 1];
    char body[256];
    const char *rpc_url = getenv("TRP_RPC_URL") ? getenv("TRP_RPC_URL") : "https://rpc.moderato.tempo.xyz";
    size_t len;
    trp_err_t err;
    FILE *f;
    int i;

    if (!path || !(f = fopen(path, "rb"))) return 0;
    len = fread(state, 1, sizeof(state), f);
    fclose(f);
    if (trp_session_load(s, state, len) != TRP_OK) {
        fprintf(stderr, "%s does not hold a saved session\n", path);
        return -1;
    }
    if (trp_session_state_request(s, body, sizeof(body)) != TRP_OK) return -1;
    for (;;) {
        long status = post_json(rpc_url, body, &rpc);
        if (status != 200) {
            fprintf(stderr, "channel read from %s failed (%ld)\n", rpc_url, status);
            return -1;
        }
        err = trp_session_sync(s, rpc.body, rpc.body_len, (uint64_t)time(NULL));
        if (err != TRP_ERR_PENDING) break;
        printf("the last channel transaction may still land; reading again in 10 s\n");
        sleep(10);
    }
    if (err != TRP_OK) {
        fprintf(stderr, "channel read failed: %s\n", rpc.body);
        return -1;
    }
    printf("restored channel 0x");
    for (i = 0; i < 32; i++) printf("%02x", s->channel_id[i]);
    if (s->closed) {
        printf(": closed on chain\n");
        return 0;
    }
    printf("\n");
    return 1;
}

/*
 * Pay for `n` requests in a channel, topping up as needed. Without a state
 * file: open a channel, then close it at the end. With one: continue the
 * channel saved there if the chain still has it, keep it open at the end,
 * and close it when n is 0.
 */
static int run_session(const char *url, int n, const char *state_path, const trp_charge_options *opt, exchange *ex)
{
    static uint8_t work[8192];
    static char credential[16384];
    trp_challenge ch;
    trp_session_request r;
    trp_session s;
    uint8_t deposit[32], salt[32], amount[32];
    uint64_t price, initial, deposited = 0, paid = 0;
    const char *env_deposit = getenv("TRP_SESSION_DEPOSIT");
    trp_err_t err;
    long status;
    int i, have;

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
        u256_from_u64(price * (uint64_t)(n ? n : 1), deposit);
    }
    if (u64_from_u256(deposit, &initial) != 0) return 2;

    if ((have = restore_state(state_path, &s)) < 0) return 1;
    if (have) {
        if (u64_from_u256(s.deposit, &deposited) != 0 || u64_from_u256(s.cumulative, &paid) != 0) return 1;
        printf("session: %llu per request, continuing at %llu of %llu deposited\n", (unsigned long long)price,
               (unsigned long long)paid, (unsigned long long)deposited);
    } else if (n == 0) {
        printf("no open channel to close\n");
        return 0;
    }

    for (i = 1; i <= n; i++) {
        uint64_t total = paid + price;
        int attempt;

        if (!have) {
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
            for (attempt = 0; attempt < 32; attempt++) printf("%02x", s.channel_id[attempt]);
            printf("\n");
            if (save_state(state_path, &s) != 0) return 1;
            status = send_credential(url, &ch, credential, ex);
            printf("request %d (open) -> %ld %s\n", i, status, ex->body);
            print_receipt(ex);
            if (status != 200) return 1;
            have = 1;
            deposited = initial;
            paid = price;
            continue;
        }

        if (total > deposited) {
            u256_from_u64(initial, amount);
            err = trp_session_top_up(&s, &ch, opt, amount, credential, sizeof(credential), work, sizeof(work));
            if (err != TRP_OK) {
                fprintf(stderr, "could not top up (%d)\n", (int)err);
                return 1;
            }
            if (save_state(state_path, &s) != 0) return 1;
            status = send_credential(url, &ch, credential, ex);
            printf("top up +%llu -> %ld\n", (unsigned long long)initial, status);
            if (status != 200 && status != 204) {
                /* Refused: forget it. No answer at all: it may be on chain, so stop rather than sign again. */
                if (status >= 400) {
                    trp_session_top_up_failed(&s);
                    save_state(state_path, &s);
                }
                printf("%s\n", ex->body);
                return 1;
            }
            trp_session_top_up_confirmed(&s);
            if (save_state(state_path, &s) != 0) return 1;
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
            if (save_state(state_path, &s) != 0) return 1;
            status = send_credential(url, &ch, credential, ex);
            /* A stale challenge earns a fresh one; sign again against it. */
            if (status != 402 || select_challenge(ex, "session", &ch) != TRP_OK) break;
        }
        printf("request %d (voucher for %llu) -> %ld %s\n", i, (unsigned long long)total, status, ex->body);
        if (status != 200) return 1;
        paid = total;
    }

    if (state_path && n > 0) {
        printf("channel kept open in %s: run again to continue, or with --session 0 to close it\n", state_path);
        return 0;
    }
    err = trp_session_close(&s, &ch, opt->signer, credential, sizeof(credential), work, sizeof(work));
    if (err != TRP_OK) {
        fprintf(stderr, "could not close (%d)\n", (int)err);
        return 1;
    }
    if (save_state(state_path, &s) != 0) return 1;
    status = send_credential(url, &ch, credential, ex);
    printf("close at %llu -> %ld %s\n", (unsigned long long)paid, status, ex->body);
    print_receipt(ex);
    return status == 200 || status == 204 ? 0 : 1;
}

int main(int argc, char **argv)
{
    static exchange ex;
    static uint8_t work[8192];      /* enough for TRP_MAX_SPLITS splits */
    static char credential[8192];
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
    const char *state_path = NULL;
    int sessions = 0, rc;

    if (argc == 6 && strcmp(argv[1], "--session") == 0 && strcmp(argv[3], "--state") == 0 && atoi(argv[2]) >= 0) {
        sessions = atoi(argv[2]);
        state_path = argv[4];
        url = argv[5];
    } else if (argc == 4 && strcmp(argv[1], "--session") == 0 && atoi(argv[2]) > 0) {
        sessions = atoi(argv[2]);
        url = argv[3];
    } else if (argc == 2) {
        url = argv[1];
    } else {
        fprintf(stderr, "usage: %s [--session <requests> [--state <file>]] <url>\n", argv[0]);
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

    if (state_path && sessions == 0) sessions = -1; /* close only */
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
        rc = run_session(url, sessions < 0 ? 0 : sessions, state_path, &opt, &ex);
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
        if (trp_receipt_parse(value, strlen(value), &receipt, receipt_scratch, sizeof(receipt_scratch)) != TRP_OK) {
            printf("receipt does not parse\n");
        } else if (result.proof) {
            /* Nothing was paid: the receipt names the challenge the proof answered. */
            printf("proof %s for challenge %.*s\n",
                   trp_receipt_verify(&receipt, "tempo", NULL) == TRP_OK ? "accepted" : "NOT accepted",
                   (int)receipt.reference.len, receipt.reference.ptr);
        } else if (result.request.fee_payer) {
            /* The server's fee-payer signature changes the hash, so only the status can be checked here. */
            printf("receipt %s (fee sponsored by the server): %.*s\n",
                   trp_receipt_verify(&receipt, "tempo", NULL) == TRP_OK ? "reports success" : "does NOT report success",
                   (int)receipt.reference.len, receipt.reference.ptr);
        } else {
            printf("receipt %s: %.*s\n",
                   trp_receipt_verify(&receipt, "tempo", result.tx_hash) == TRP_OK
                       ? "matches the transaction this device signed"
                       : "does NOT match",
                   (int)receipt.reference.len, receipt.reference.ptr);
        }
    }
    curl_global_cleanup();
    return status == 200 ? 0 : 1;
}

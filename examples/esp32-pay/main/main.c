/*
 * An ESP32 pays an MPP endpoint on Tempo: join Wi-Fi, set the clock, then
 * GET the URL every CONFIG_TRP_INTERVAL_S seconds; on 402, answer the Tempo
 * charge challenge with a payment signed by the device key, and retry.
 *
 * The key lives in the ATECC608A of an ESP32-WROOM-32SE, or, for boards
 * without one, in the firmware (testnet only). Configure with
 * `idf.py menuconfig` -> Transponder example. See README.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/hex.h"
#include "transponder/receipt.h"
#include "transponder/tempo.h"

#if CONFIG_TRP_SIGNER_ATECC608
#include "cryptoauthlib.h"
#include "trp_atecc608_signer.h"
#else
#include "trp_mbedtls_signer.h"
#endif

static const char *TAG = "transponder";

/* ---- Wi-Fi --------------------------------------------------------------- */

#define WIFI_CONNECTED BIT0
static EventGroupHandle_t wifi_events;

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        xEventGroupClearBits(wifi_events, WIFI_CONNECTED);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_events, WIFI_CONNECTED);
    }
}

static void wifi_start(void)
{
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t config = {0};

    wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL));
    strlcpy((char *)config.sta.ssid, CONFIG_TRP_WIFI_SSID, sizeof(config.sta.ssid));
    strlcpy((char *)config.sta.password, CONFIG_TRP_WIFI_PASSWORD, sizeof(config.sta.password));
    /* With a password, refuse open and WEP networks posing as this one. */
    if (CONFIG_TRP_WIFI_PASSWORD[0]) config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &config));
    ESP_ERROR_CHECK(esp_wifi_start());
    xEventGroupWaitBits(wifi_events, WIFI_CONNECTED, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi connected");
}

/* Transactions carry validity windows, so the clock must be right. */
static void clock_start(void)
{
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&config);
    while (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(10000)) != ESP_OK) ESP_LOGW(TAG, "waiting for the time");
    ESP_LOGI(TAG, "time set: %lld", (long long)time(NULL));
}

/* ---- HTTP ---------------------------------------------------------------- */

typedef struct {
    char challenge[4096]; /* WWW-Authenticate values, comma-joined */
    size_t challenge_len;
    char receipt[1024];
    char body[512];
    size_t body_len;
} exchange;

static esp_err_t on_http_event(esp_http_client_event_t *evt)
{
    exchange *ex = (exchange *)evt->user_data;
    size_t n;

    if (evt->event_id == HTTP_EVENT_ON_HEADER) {
        if (strcasecmp(evt->header_key, "www-authenticate") == 0) {
            n = strlen(evt->header_value);
            if (ex->challenge_len + n + 3 < sizeof(ex->challenge)) {
                if (ex->challenge_len) {
                    memcpy(ex->challenge + ex->challenge_len, ", ", 2);
                    ex->challenge_len += 2;
                }
                memcpy(ex->challenge + ex->challenge_len, evt->header_value, n + 1);
                ex->challenge_len += n;
            }
        } else if (strcasecmp(evt->header_key, "payment-receipt") == 0) {
            strlcpy(ex->receipt, evt->header_value, sizeof(ex->receipt));
        }
    } else if (evt->event_id == HTTP_EVENT_ON_DATA) {
        n = sizeof(ex->body) - 1 - ex->body_len;
        if ((size_t)evt->data_len < n) n = (size_t)evt->data_len;
        memcpy(ex->body + ex->body_len, evt->data, n);
        ex->body_len += n;
        ex->body[ex->body_len] = '\0';
    }
    return ESP_OK;
}

#define CREDENTIAL_CAP 4608 /* a charge with TRP_MAX_SPLITS splits */

static int http_get(const char *url, const char *header, const char *value, exchange *ex)
{
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = on_http_event,
        .user_data = ex,
        .timeout_ms = 30000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        /* Each request header must fit whole in the send buffer (512 bytes by default). */
        .buffer_size_tx = CREDENTIAL_CAP + 512,
        /* A redirect would carry the signed payment to another host. */
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client;
    int status = -1;

    memset(ex, 0, sizeof(*ex));
    client = esp_http_client_init(&config);
    if (!client) return -1;
    if (header && esp_http_client_set_header(client, header, value) != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    if (esp_http_client_perform(client) == ESP_OK) status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    return status;
}

/* ---- The device key ------------------------------------------------------ */

static trp_signer signer;

static void signer_start(void)
{
    uint8_t address[TRP_ADDRESS_LEN];
    char hex[2 * TRP_ADDRESS_LEN + 1];

#if CONFIG_TRP_SIGNER_ATECC608
    static trp_atecc608_key key;
    ESP_ERROR_CHECK(atcab_init(&cfg_ateccx08a_i2c_default) == ATCA_SUCCESS ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(trp_atecc608_signer_init(&signer, &key, CONFIG_TRP_ATECC608_SLOT) == TRP_OK ? ESP_OK : ESP_FAIL);
    ESP_LOGI(TAG, "signing with the ATECC608A, slot %d", CONFIG_TRP_ATECC608_SLOT);
#else
    static trp_mbedtls_key key;
    uint8_t private_key[32];
    size_t n = 0;
    if (trp_hex_decode(CONFIG_TRP_DEVICE_KEY, strlen(CONFIG_TRP_DEVICE_KEY), private_key, sizeof(private_key), &n) !=
            TRP_OK ||
        n != 32 || trp_mbedtls_signer_import(&signer, &key, private_key) != TRP_OK) {
        ESP_LOGE(TAG, "CONFIG_TRP_DEVICE_KEY must be 32 bytes of hex");
        abort();
    }
    memset(private_key, 0, sizeof(private_key));
    ESP_LOGW(TAG, "signing with a software key: testnet only");
#endif
    /* The owner authorizes this address as an access key (tools/testnet/setup.mjs). */
    trp_p256_address(signer.public_key, address);
    trp_hex_encode(address, sizeof(address), 0, hex, sizeof(hex));
    ESP_LOGI(TAG, "device key address 0x%s", hex);
}

/* ---- One paid request ---------------------------------------------------- */

static uint8_t hex_bytes(const char *name, const char *value, uint8_t *out, size_t len)
{
    size_t n = 0;
    if (trp_hex_decode(value, strlen(value), out, len, &n) != TRP_OK || n != len) {
        ESP_LOGE(TAG, "%s must be %u bytes of hex", name, (unsigned)len);
        return 0;
    }
    return 1;
}

static void pay_once(void)
{
    static exchange ex;
    static char wire[sizeof(ex.challenge)], scratch[2 * sizeof(ex.challenge) + 16];
    static char credential[CREDENTIAL_CAP], receipt_scratch[2 * sizeof(ex.receipt) + 16];
    static uint8_t work[8192];
    static uint8_t owner[TRP_ADDRESS_LEN], fee_token[TRP_ADDRESS_LEN];
    static uint64_t chain_id = CONFIG_TRP_CHAIN_ID;
    trp_spend_policy policy;
    trp_charge_options opt;
    trp_charge_result result;
    trp_challenge ch;
    trp_receipt receipt;
    trp_err_t err;
    uint64_t now = (uint64_t)time(NULL);
    int status;

    if (!hex_bytes("CONFIG_TRP_OWNER", CONFIG_TRP_OWNER, owner, sizeof(owner)) ||
        !hex_bytes("CONFIG_TRP_FEE_TOKEN", CONFIG_TRP_FEE_TOKEN, fee_token, sizeof(fee_token)))
        return;

    status = http_get(CONFIG_TRP_URL, NULL, NULL, &ex);
    ESP_LOGI(TAG, "GET %s -> %d", CONFIG_TRP_URL, status);
    if (status != 402) return;
    memcpy(wire, ex.challenge, ex.challenge_len + 1);
    if ((err = trp_challenge_select(wire, ex.challenge_len, "tempo", "charge", &ch, scratch, sizeof(scratch))) !=
        TRP_OK) {
        ESP_LOGE(TAG, "no Tempo charge challenge (%d)", (int)err);
        return;
    }

    /* The device's own limits: the server only asks, this decides. */
    memset(&policy, 0, sizeof(policy));
    trp_u256_from_decimal(CONFIG_TRP_MAX_AMOUNT, strlen(CONFIG_TRP_MAX_AMOUNT), policy.max_amount);
    policy.chain_ids = &chain_id;
    policy.chain_id_count = 1;

    memset(&opt, 0, sizeof(opt));
    opt.owner = owner;
    opt.signer = &signer;
    opt.policy = &policy;
    opt.now = now;
    opt.valid_after = now - 60 - esp_random() % 86400; /* a random past second */
    opt.gas_limit = CONFIG_TRP_GAS;
    opt.max_fee_per_gas = strtoull(CONFIG_TRP_MAX_FEE, NULL, 10);
    opt.max_priority_fee_per_gas = strtoull(CONFIG_TRP_PRIORITY_FEE, NULL, 10);
    opt.fee_token = fee_token;
    opt.client_id.ptr = "transponder";
    opt.client_id.len = 11;

    err = trp_tempo_charge(&ch, &opt, credential, sizeof(credential), work, sizeof(work), &result);
    if (err == TRP_ERR_DENIED) {
        ESP_LOGW(TAG, "refused: the challenge is outside this device's spending policy");
        return;
    }
    if (err != TRP_OK) {
        ESP_LOGE(TAG, "could not build the payment (%d)", (int)err);
        return;
    }

    status = http_get(CONFIG_TRP_URL, trp_challenge_credential_header(&ch), credential, &ex);
    ESP_LOGI(TAG, "GET with payment -> %d: %s", status, ex.body);
    if (ex.receipt[0] &&
        trp_receipt_parse(ex.receipt, strlen(ex.receipt), &receipt, receipt_scratch, sizeof(receipt_scratch)) ==
            TRP_OK)
        ESP_LOGI(TAG, "receipt %s: %.*s",
                 trp_receipt_verify(&receipt, "tempo",
                                    result.request.fee_payer || result.proof ? NULL : result.tx_hash) == TRP_OK
                     ? "verified"
                     : "does NOT match",
                 (int)receipt.reference.len, receipt.reference.ptr);
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    signer_start();
    wifi_start();
    clock_start();
    for (;;) {
        pay_once();
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TRP_INTERVAL_S * 1000));
    }
}

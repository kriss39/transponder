# The signer port is built by the transponder component (Component config -> Transponder).
idf_component_register(SRCS main.c
                       INCLUDE_DIRS .
                       PRIV_REQUIRES kriss39__transponder espressif__esp-cryptoauthlib esp_wifi esp_netif
                                     esp_event esp_http_client nvs_flash mbedtls)

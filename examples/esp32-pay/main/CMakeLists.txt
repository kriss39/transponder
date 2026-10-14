# The signer ports are plain sources next to the component; build the one in use.
set(ports ../../../ports)
set(srcs main.c)
set(includes .)
if(CONFIG_TRP_SIGNER_ATECC608)
    list(APPEND srcs ${ports}/atecc608/trp_atecc608_signer.c)
    list(APPEND includes ${ports}/atecc608)
else()
    list(APPEND srcs ${ports}/mbedtls/trp_mbedtls_signer.c)
    list(APPEND includes ${ports}/mbedtls)
endif()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${includes}
                       PRIV_REQUIRES transponder espressif__esp-cryptoauthlib esp_wifi esp_netif esp_event
                                     esp_http_client nvs_flash mbedtls)

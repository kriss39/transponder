# ESP-IDF picks up this file as a component. Other CMake projects get a plain
# static library. The host test build uses the Makefile.

if(ESP_PLATFORM)
    # The signer port follows the Kconfig choice. Requirements cannot: ESP-IDF
    # expands them before sdkconfig exists, so both drivers are always required
    # (mbedTLS ships with ESP-IDF; esp-cryptoauthlib comes from idf_component.yml).
    set(src_dirs "src")
    if(CONFIG_TRP_SIGNER_ATECC608)
        list(APPEND src_dirs "ports/atecc608")
    elseif(CONFIG_TRP_SIGNER_SOFTWARE)
        list(APPEND src_dirs "ports/mbedtls")
    endif()
    idf_component_register(SRC_DIRS ${src_dirs}
                           INCLUDE_DIRS "include" "ports/atecc608" "ports/mbedtls"
                           REQUIRES mbedtls
                           PRIV_REQUIRES espressif__esp-cryptoauthlib)
    return()
endif()

cmake_minimum_required(VERSION 3.16)
project(transponder C)

file(GLOB TRANSPONDER_SOURCES CONFIGURE_DEPENDS src/*.c)
add_library(transponder STATIC ${TRANSPONDER_SOURCES})
target_include_directories(transponder PUBLIC include)
set_target_properties(transponder PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)

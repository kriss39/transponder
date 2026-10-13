# Host build: compiles the library and runs the unit tests on this machine.
# On ESP-IDF, the root CMakeLists.txt is used instead.

CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror
CPPFLAGS = -Iinclude

SRC = $(wildcard src/*.c)
TEST_SRC = $(filter-out tests/port_%.c,$(wildcard tests/*.c))
BUILD = build

.PHONY: all test asan test-mbedtls pay clean

all: $(BUILD)/libtransponder.a

$(BUILD)/%.o: src/%.c $(wildcard include/transponder/*.h) src/internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) -c $< -o $@

$(BUILD)/libtransponder.a: $(SRC:src/%.c=$(BUILD)/%.o)
	$(AR) rcs $@ $^

$(BUILD)/run_tests: $(SRC) $(TEST_SRC) $(wildcard include/transponder/*.h) src/internal.h tests/test.h tests/conformance_vectors.h tests/tempo_vectors.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) $(SRC) $(TEST_SRC) -o $@

test: $(BUILD)/run_tests
	./$(BUILD)/run_tests

# Address and undefined-behaviour sanitizers.
asan: | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		$(SRC) $(TEST_SRC) -o $(BUILD)/run_tests_asan
	./$(BUILD)/run_tests_asan

# The software signer in ports/mbedtls (needs mbedTLS; on macOS: brew install mbedtls).
MBEDTLS_PREFIX ?= $(shell brew --prefix mbedtls 2>/dev/null)
MBEDTLS_CFLAGS ?= $(if $(MBEDTLS_PREFIX),-I$(MBEDTLS_PREFIX)/include)
MBEDTLS_LIBS ?= $(if $(MBEDTLS_PREFIX),-L$(MBEDTLS_PREFIX)/lib) -lmbedcrypto

test-mbedtls: | $(BUILD)
	$(CC) $(CPPFLAGS) $(MBEDTLS_CFLAGS) $(WARNINGS) $(CFLAGS) $(SRC) ports/mbedtls/trp_mbedtls_signer.c \
		tests/port_mbedtls.c $(MBEDTLS_LIBS) -o $(BUILD)/run_tests_mbedtls
	./$(BUILD)/run_tests_mbedtls

# Host demo: pay an MPP endpoint from this computer (see examples/host-pay/pay.c).
pay: | $(BUILD)
	$(CC) $(CPPFLAGS) $(MBEDTLS_CFLAGS) $(WARNINGS) -Wno-conversion $(CFLAGS) $(SRC) \
		ports/mbedtls/trp_mbedtls_signer.c examples/host-pay/pay.c $(MBEDTLS_LIBS) -lcurl -o $(BUILD)/pay

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

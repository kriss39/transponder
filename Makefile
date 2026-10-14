# Host build: compiles the library and runs the unit tests on this machine.
# On ESP-IDF, the root CMakeLists.txt is used instead.

CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror
CPPFLAGS = -Iinclude

SRC = $(wildcard src/*.c)
TEST_SRC = $(filter-out tests/port_%.c,$(wildcard tests/*.c))
BUILD = build

.PHONY: all test asan test-mbedtls pay pay-enclave enclave-key conformance-adapter fuzz fuzz-run fuzz-replay stack clean

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

# Fuzzing (fuzz/). libFuzzer needs clang with -fsanitize=fuzzer; Apple's clang
# lacks it, so on macOS this uses Homebrew's (brew install llvm).
FUZZ_CC ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang) clang)
# Homebrew's clang emits objects Apple's linker cannot read; link with its lld.
FUZZ_LDFLAGS ?= $(if $(findstring /opt/homebrew/,$(FUZZ_CC)),-fuse-ld=lld)
FUZZ_TARGETS = parse pay
FUZZ_TIME ?= 60
FUZZ_FLAGS = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer

fuzz: $(FUZZ_TARGETS:%=$(BUILD)/fuzz_%)

$(BUILD)/fuzz_%: fuzz/fuzz_%.c $(SRC) $(wildcard include/transponder/*.h) src/internal.h | $(BUILD)
	$(FUZZ_CC) $(CPPFLAGS) $(WARNINGS) $(FUZZ_FLAGS) -fsanitize=fuzzer $(FUZZ_LDFLAGS) $(SRC) $< -o $@

# Fuzz each target for FUZZ_TIME seconds, starting from the seeds in fuzz/corpus.
fuzz-run: fuzz
	for t in $(FUZZ_TARGETS); do \
		mkdir -p $(BUILD)/corpus/$$t && cp fuzz/corpus/$$t/* $(BUILD)/corpus/$$t/ && \
		./$(BUILD)/fuzz_$$t $(BUILD)/corpus/$$t -dict=fuzz/mpp.dict -max_total_time=$(FUZZ_TIME) \
			-print_final_stats=1 || exit 1; \
	done

# Replay the seed corpus under the sanitizers, with any compiler.
fuzz-replay: | $(BUILD)
	for t in $(FUZZ_TARGETS); do \
		$(CC) $(CPPFLAGS) $(WARNINGS) $(FUZZ_FLAGS) $(SRC) fuzz/fuzz_$$t.c fuzz/replay.c \
			-o $(BUILD)/replay_$$t && ./$(BUILD)/replay_$$t fuzz/corpus/$$t/* || exit 1; \
	done

# Stack used by each entry point on this machine (tools/stack).
stack: | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) $(SRC) tools/stack/stack_usage.c -lpthread -o $(BUILD)/stack_usage
	./$(BUILD)/stack_usage

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

# Apple Secure Enclave signer (Apple silicon Macs). swiftc links the C and Swift halves.
ENCLAVE_SWIFT = ports/apple/trp_secure_enclave.swift
ENCLAVE_C = ports/apple/trp_secure_enclave.c

enclave-key: | $(BUILD)
	mkdir -p $(BUILD)/enclave-key.o.d
	cd $(BUILD)/enclave-key.o.d && $(CC) -I../../include $(WARNINGS) $(CFLAGS) -c \
		$(addprefix ../../,$(SRC) $(ENCLAVE_C) examples/host-pay/enclave_key.c)
	swiftc -O -parse-as-library $(ENCLAVE_SWIFT) $(BUILD)/enclave-key.o.d/*.o -o $(BUILD)/enclave-key

pay-enclave: | $(BUILD)
	mkdir -p $(BUILD)/pay-enclave.o.d
	cd $(BUILD)/pay-enclave.o.d && $(CC) -I../../include $(MBEDTLS_CFLAGS) $(WARNINGS) -Wno-conversion \
		$(CFLAGS) -DTRP_WITH_ENCLAVE -c \
		$(addprefix ../../,$(SRC) $(ENCLAVE_C) ports/mbedtls/trp_mbedtls_signer.c examples/host-pay/pay.c)
	swiftc -O -parse-as-library $(ENCLAVE_SWIFT) $(BUILD)/pay-enclave.o.d/*.o $(MBEDTLS_LIBS) -lcurl -o $(BUILD)/pay

# Adapter for the tempoxyz/mpp-tools conformance runner (see tools/conformance).
conformance-adapter: | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) -Wno-conversion $(CFLAGS) $(SRC) tools/conformance/adapter.c \
		-o $(BUILD)/trp-conformance-adapter

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

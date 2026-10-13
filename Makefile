# Host build: compiles the library and runs the unit tests on this machine.
# On ESP-IDF, the root CMakeLists.txt is used instead.

CC ?= cc
CFLAGS ?= -O2 -g
WARNINGS = -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror
CPPFLAGS = -Iinclude

SRC = $(wildcard src/*.c)
TEST_SRC = $(wildcard tests/*.c)
BUILD = build

.PHONY: all test asan clean

all: $(BUILD)/libtransponder.a

$(BUILD)/%.o: src/%.c $(wildcard include/transponder/*.h) src/internal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) -c $< -o $@

$(BUILD)/libtransponder.a: $(SRC:src/%.c=$(BUILD)/%.o)
	$(AR) rcs $@ $^

$(BUILD)/run_tests: $(SRC) $(TEST_SRC) $(wildcard include/transponder/*.h) src/internal.h tests/test.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) $(CFLAGS) $(SRC) $(TEST_SRC) -o $@

test: $(BUILD)/run_tests
	./$(BUILD)/run_tests

# Address and undefined-behaviour sanitizers.
asan: | $(BUILD)
	$(CC) $(CPPFLAGS) $(WARNINGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		$(SRC) $(TEST_SRC) -o $(BUILD)/run_tests_asan
	./$(BUILD)/run_tests_asan

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

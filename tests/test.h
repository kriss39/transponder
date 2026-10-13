#ifndef TRANSPONDER_TEST_H
#define TRANSPONDER_TEST_H

/* A tiny test harness: no dependencies, runs the same on a host or a board. */

#include <stdio.h>
#include <string.h>

#include "transponder/hex.h"

extern int trp_test_failures;
extern int trp_test_checks;

#define CHECK(cond)                                                       \
    do {                                                                  \
        trp_test_checks++;                                                \
        if (!(cond)) {                                                    \
            trp_test_failures++;                                          \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                 \
    } while (0)

/* Compare a byte buffer with an expected hex string (no 0x prefix). */
#define CHECK_HEX(buf, len, expected_hex)                                 \
    do {                                                                  \
        char got_[2 * 1024 + 1];                                          \
        trp_test_checks++;                                                \
        if (trp_hex_encode((buf), (len), 0, got_, sizeof(got_)) != TRP_OK \
            || strcmp(got_, (expected_hex)) != 0) {                       \
            trp_test_failures++;                                          \
            printf("  FAIL %s:%d\n    want %s\n    got  %s\n", __FILE__,  \
                   __LINE__, (expected_hex), got_);                       \
        }                                                                 \
    } while (0)

void test_hex(void);
void test_keccak(void);
void test_rlp(void);
void test_base64url(void);
void test_json(void);
void test_challenge(void);
void test_tempo(void);

#endif

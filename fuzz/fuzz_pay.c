/*
 * Fuzz the payment paths with a hostile server: the input is the challenge's
 * `request` JSON, and everything the device would do with it runs, from
 * request parsing to the signed credential. A charge goes through
 * trp_tempo_charge; a session through open, voucher, top-up and close. The
 * signer is fake and the policy allows anything, so the fuzzer reaches the
 * encoders. The first byte picks charge or session and whether the challenge
 * has an expiry.
 *
 *   make fuzz && ./build/fuzz_pay fuzz/corpus/pay -dict=fuzz/mpp.dict
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transponder/base64url.h"
#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/session.h"

#define MAX_INPUT 2048

static trp_err_t fake_sign(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    (void)ctx;
    memcpy(r, digest, 32);
    memcpy(s, digest, 32);
    r[0] |= 1; /* never zero */
    s[0] |= 1;
    return TRP_OK;
}

/* A successful call must leave a NUL-terminated string inside the buffer. */
static void check_out(trp_err_t err, const char *out, size_t cap)
{
    if (err == TRP_OK && (memchr(out, '\0', cap) == NULL || out[0] == '\0')) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char request[2 * MAX_INPUT], wire[3 * MAX_INPUT], scratch[6 * MAX_INPUT + 16];
    static char out[16384];
    static uint8_t work[8192];
    static const uint8_t owner[20] = {0xa1, 0x1c, 0xe0};
    trp_signer signer;
    trp_spend_policy policy;
    trp_charge_options opt;
    trp_charge_result result;
    trp_challenge ch;
    trp_session_request r;
    trp_session s;
    uint8_t salt[32] = {7}, amount[32];
    int session;

    if (size < 1 || size > MAX_INPUT) return 0;
    session = data[0] & 1;
    if (trp_base64url_encode(data + 1, size - 1, request, sizeof(request)) != TRP_OK) return 0;
    snprintf(wire, sizeof(wire), "Payment id=\"f\", realm=\"r\", method=\"tempo\", intent=\"%s\", request=\"%s\"%s",
             session ? "session" : "charge", request, data[0] & 2 ? ", expires=\"2023-11-14T22:14:00Z\"" : "");
    if (trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch)) != TRP_OK) return 0;

    memset(&signer, 0, sizeof(signer));
    signer.sign_digest = fake_sign;
    memset(signer.public_key, 0x42, sizeof(signer.public_key));
    signer.pre_hash = data[0] & 4 ? 1 : 0;
    memset(&policy, 0, sizeof(policy));
    memset(policy.max_amount, 0xff, sizeof(policy.max_amount));
    memset(&opt, 0, sizeof(opt));
    opt.owner = owner;
    opt.signer = &signer;
    opt.policy = &policy;
    opt.now = 1700000000;
    opt.valid_after = 1699990000;
    opt.gas_limit = 400000;
    opt.max_fee_per_gas = 30000000000u;
    opt.client_id.ptr = "fuzz";
    opt.client_id.len = 4;

    if (!session) {
        check_out(trp_tempo_charge(&ch, &opt, out, sizeof(out), work, sizeof(work), &result), out, sizeof(out));
        return 0;
    }

    if (trp_session_request_parse(&ch, &r) != TRP_OK) return 0;
    /* Deposit the price: the smallest deposit open accepts. */
    check_out(trp_session_open(&ch, &opt, r.price, salt, &s, out, sizeof(out), work, sizeof(work)), out, sizeof(out));
    if (trp_session_open(&ch, &opt, r.price, salt, &s, out, sizeof(out), work, sizeof(work)) != TRP_OK) return 0;
    /* The open's voucher covers the price, which is the whole deposit. */
    if (memcmp(s.cumulative, s.deposit, 32) != 0) abort();
    check_out(trp_session_voucher(&s, &ch, &signer, s.cumulative, out, sizeof(out), work, sizeof(work)), out,
              sizeof(out));
    memset(amount, 0, sizeof(amount));
    amount[31] = 1;
    check_out(trp_session_top_up(&s, &ch, &opt, amount, out, sizeof(out), work, sizeof(work)), out, sizeof(out));
    check_out(trp_session_close(&s, &ch, &signer, out, sizeof(out), work, sizeof(work)), out, sizeof(out));
    return 0;
}

/*
 * Measure how much stack each public entry point uses, on this machine:
 * run it on a thread whose stack is filled with a pattern, then see how much
 * of the pattern is gone. The signer is a stub, so the figures leave out the
 * signer's own stack (a secure element needs little; software P-256 more).
 *
 *   make stack
 *
 * Frame sizes depend on the compiler and the CPU, so treat the numbers as an
 * estimate for a microcontroller and leave headroom.
 */

#define _POSIX_C_SOURCE 200112L

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/hex.h"
#include "transponder/session.h"
#include "../../tests/tempo_vectors.h"

#define STACK_SIZE (256 * 1024)
#define PATTERN 0xa5

static char scratch[4096], out[8192];
static uint8_t work[8192];
static trp_signer signer;
static trp_spend_policy policy;
static trp_charge_options opt;
static trp_challenge ch;
static trp_session session;
static const uint8_t OWNER[20] = {0xa1, 0x1c, 0xe0};

static trp_err_t stub_sign(void *ctx, const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    (void)ctx;
    memcpy(r, digest, 32);
    memcpy(s, digest, 32);
    r[0] |= 1;
    s[0] = 1;
    return TRP_OK;
}

static void setup(uint64_t now)
{
    memset(&signer, 0, sizeof(signer));
    signer.sign_digest = stub_sign;
    size_t n;

    trp_hex_decode(TV_PUBLIC_KEY, 128, signer.public_key, 64, &n);
    memset(&policy, 0, sizeof(policy));
    memset(policy.max_amount, 0xff, sizeof(policy.max_amount));
    memset(&opt, 0, sizeof(opt));
    opt.owner = OWNER;
    opt.signer = &signer;
    opt.policy = &policy;
    opt.now = now;
    opt.valid_after = 1700000000;
    opt.gas_limit = 400000;
    opt.max_fee_per_gas = 30000000000u;
}

static trp_err_t job_none(void)
{
    return TRP_OK;
}

static trp_err_t job_parse(void)
{
    const char *wire = CHARGE_VECTORS[2].wire;
    return trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch));
}

static trp_err_t job_charge(void)
{
    trp_charge_result result;
    const char *wire = CHARGE_VECTORS[2].wire; /* two splits: three calls */
    trp_err_t err = trp_challenge_parse(wire, strlen(wire), &ch, scratch, sizeof(scratch));
    if (err != TRP_OK) return err;
    setup(CHARGE_VECTORS[2].now);
    return trp_tempo_charge(&ch, &opt, out, sizeof(out), work, sizeof(work), &result);
}

static void u256(const char *dec, uint8_t v[32])
{
    trp_u256_from_decimal(dec, strlen(dec), v);
}

static trp_err_t session_challenge(void)
{
    setup(SV_NOW);
    return trp_challenge_parse(SV_WIRE, strlen(SV_WIRE), &ch, scratch, sizeof(scratch));
}

static trp_err_t job_open(void)
{
    uint8_t deposit[32], salt[32] = {1};
    trp_err_t err = session_challenge();
    if (err != TRP_OK) return err;
    u256(SV_DEPOSIT, deposit);
    return trp_session_open(&ch, &opt, deposit, salt, &session, out, sizeof(out), work, sizeof(work));
}

static trp_err_t job_voucher(void)
{
    uint8_t amount[32];
    u256(SV_VOUCHER, amount);
    return trp_session_voucher(&session, &ch, &signer, amount, out, sizeof(out), work, sizeof(work));
}

static trp_err_t job_top_up(void)
{
    uint8_t amount[32];
    u256(SV_ADDITIONAL, amount);
    return trp_session_top_up(&session, &ch, &opt, amount, out, sizeof(out), work, sizeof(work));
}

static trp_err_t job_close(void)
{
    return trp_session_close(&session, &ch, &signer, out, sizeof(out), work, sizeof(work));
}

/* After a restart: load the saved session, then sync it with the chain's answer. */
static trp_err_t job_restore(void)
{
    static const char response[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" SV_STATE_RESULT "\"}";
    uint8_t state[TRP_SESSION_STATE_LEN];
    trp_err_t err;
    trp_session_save(&session, state);
    if ((err = trp_session_load(&session, state, sizeof(state))) != TRP_OK) return err;
    return trp_session_sync(&session, response, sizeof(response) - 1, SV_NOW);
}

typedef struct {
    const char *name;
    trp_err_t (*run)(void);
    trp_err_t err;
} job;

static void *run_job(void *arg)
{
    job *j = (job *)arg;
    j->err = j->run();
    return NULL;
}

int main(void)
{
    job jobs[] = {
        {"(thread start-up only)", job_none, TRP_OK},
        {"trp_challenge_parse", job_parse, TRP_OK},
        {"trp_tempo_charge (with parse)", job_charge, TRP_OK},
        {"trp_session_open (with parse)", job_open, TRP_OK},
        {"trp_session_voucher", job_voucher, TRP_OK},
        {"trp_session_top_up", job_top_up, TRP_OK},
        {"trp_session_close", job_close, TRP_OK},
        {"trp_session_load + _sync", job_restore, TRP_OK},
    };
    void *stack;
    size_t i, used;
    int failed = 0;

    if (posix_memalign(&stack, 65536, STACK_SIZE) != 0) return 1;
    for (i = 0; i < sizeof(jobs) / sizeof(jobs[0]); i++) {
        pthread_attr_t attr;
        pthread_t thread;

        memset(stack, PATTERN, STACK_SIZE);
        pthread_attr_init(&attr);
        if (pthread_attr_setstack(&attr, stack, STACK_SIZE) != 0 ||
            pthread_create(&thread, &attr, run_job, &jobs[i]) != 0) {
            fprintf(stderr, "cannot start a thread\n");
            return 1;
        }
        pthread_join(thread, NULL);
        pthread_attr_destroy(&attr);
        /* The stack grows down: the lowest touched byte marks the deepest point. */
        for (used = STACK_SIZE; used > 0 && ((uint8_t *)stack)[STACK_SIZE - used] == PATTERN; used--) {
        }
        printf("%-32s %6zu bytes%s\n", jobs[i].name, used, jobs[i].err == TRP_OK ? "" : "  (FAILED)");
        failed |= jobs[i].err != TRP_OK;
    }
    free(stack);
    return failed;
}

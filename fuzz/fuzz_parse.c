/*
 * Fuzz the parsers that read what a server sends: WWW-Authenticate,
 * Payment-Receipt and JSON, and what a device reads back after a restart:
 * a saved session and the RPC's answer about its channel. The first byte
 * picks the parser.
 *
 *   make fuzz && ./build/fuzz_parse fuzz/corpus/parse -dict=fuzz/mpp.dict
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "transponder/challenge.h"
#include "transponder/charge.h"
#include "transponder/json.h"
#include "transponder/receipt.h"
#include "transponder/session.h"

#define MAX_INPUT 4096

static char scratch[2 * MAX_INPUT + 16];

/* Every string the parser hands back must lie inside the scratch buffer and be NUL-terminated. */
static void check_str(trp_str s)
{
    if (!s.ptr) return;
    if (s.ptr < scratch || s.ptr + s.len >= scratch + sizeof(scratch) || s.ptr[s.len] != '\0') abort();
}

static void walk(const trp_json *v, int depth)
{
    trp_json item;
    size_t cursor = 0;
    char buf[256];
    size_t n;
    uint64_t u;
    int b;

    if (depth > 16) abort(); /* deeper than the parser allows */
    switch (v->type) {
    case TRP_JSON_ARRAY:
        while (trp_json_next(v, &cursor, &item) == TRP_OK) walk(&item, depth + 1);
        break;
    case TRP_JSON_OBJECT:
        if (trp_json_get(v, "amount", &item) == TRP_OK) walk(&item, depth + 1);
        if (trp_json_get(v, "methodDetails", &item) == TRP_OK) walk(&item, depth + 1);
        break;
    case TRP_JSON_STRING:
        if (trp_json_get_string(v, buf, sizeof(buf), &n) == TRP_OK && (n >= sizeof(buf) || buf[n] != '\0')) abort();
        break;
    default:
        (void)trp_json_get_uint64(v, &u);
        (void)trp_json_get_bool(v, &b);
        break;
    }
}

/* A saved session must load to the same bytes; a sync must keep the session's invariants. */
static void restart(const uint8_t *data, size_t size, int sync)
{
    static trp_session s;
    trp_session before;
    uint8_t again[TRP_SESSION_STATE_LEN];
    trp_err_t err;

    if (!sync) {
        if (trp_session_load(&s, data, size) != TRP_OK) return;
        trp_session_save(&s, again);
        if (memcmp(again, data, sizeof(again)) != 0) abort();
        return;
    }
    memset(&s, 0, sizeof(s));
    s.deposit[31] = 100;
    s.pending_top_up[31] = 50;
    s.cumulative[31] = 40;
    s.tx_valid_before = 1000;
    before = s;
    err = trp_session_sync(&s, (const char *)data, size, size & 1 ? 1000 : 2000);
    if (err != TRP_OK) {
        if (memcmp(&s, &before, sizeof(s)) != 0) abort(); /* failures change nothing */
        return;
    }
    if (s.pending_top_up[31] != 0) abort();
    if (!s.closed && memcmp(s.cumulative, s.deposit, 32) > 0) abort();
    if (memcmp(s.cumulative, before.cumulative, 32) < 0) abort(); /* never down */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    trp_challenge ch;
    trp_receipt receipt;
    trp_charge_request charge;
    trp_session_request session;
    trp_json root;
    const char *text;
    size_t len;

    if (size < 1 || size > MAX_INPUT) return 0;
    text = (const char *)data + 1;
    len = size - 1;
    if (data[0] >= 0xfe) {
        restart(data + 1, len, data[0] == 0xff);
        return 0;
    }

    switch (data[0] % 4) {
    case 0:
        if (trp_challenge_parse(text, len, &ch, scratch, sizeof(scratch)) != TRP_OK) break;
        check_str(ch.id);
        check_str(ch.realm);
        check_str(ch.method);
        check_str(ch.intent);
        check_str(ch.request);
        check_str(ch.description);
        (void)trp_challenge_credential_header(&ch);
        (void)trp_charge_request_parse(&ch, &charge);
        (void)trp_session_request_parse(&ch, &session);
        break;
    case 1:
        if (trp_challenge_select(text, len, "tempo", data[0] & 4 ? "session" : "charge", &ch, scratch,
                                 sizeof(scratch)) != TRP_OK)
            break;
        check_str(ch.id);
        check_str(ch.request);
        break;
    case 2:
        if (trp_receipt_parse(text, len, &receipt, scratch, sizeof(scratch)) != TRP_OK) break;
        check_str(receipt.reference);
        (void)trp_receipt_verify(&receipt, "tempo", NULL);
        break;
    default:
        if (trp_json_parse(text, len, &root) == TRP_OK) walk(&root, 0);
        break;
    }
    return 0;
}

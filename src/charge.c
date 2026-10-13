#include "transponder/charge.h"

#include <string.h>

#include "transponder/credential.h"
#include "transponder/json.h"
#include "transponder/keccak.h"
#include "internal.h"

/* ---- 256-bit helpers ----------------------------------------------------- */

static int u256_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

/* acc += x; returns non-zero on overflow. */
static int u256_add(uint8_t acc[32], const uint8_t x[32])
{
    unsigned carry = 0;
    int i;

    for (i = 31; i >= 0; i--) {
        unsigned v = (unsigned)acc[i] + x[i] + carry;
        acc[i] = (uint8_t)v;
        carry = v >> 8;
    }
    return carry != 0;
}

/* out = a - b, for a >= b. */
static void u256_sub(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    int i, borrow = 0;

    for (i = 31; i >= 0; i--) {
        int v = (int)a[i] - (int)b[i] - borrow;
        borrow = v < 0;
        out[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
}

/* ---- the request --------------------------------------------------------- */

static trp_err_t optional(trp_err_t err)
{
    return err == TRP_ERR_NOT_FOUND ? TRP_OK : err;
}

static trp_err_t read_split(const trp_json *item, trp_charge_split *s)
{
    trp_err_t err;

    if (item->type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;
    if (trp__json_u256(item, "amount", s->amount) != TRP_OK) return TRP_ERR_INVALID;
    if (trp__is_zero(s->amount, TRP_U256_LEN)) return TRP_ERR_INVALID;
    if (trp__json_hex(item, "recipient", s->recipient, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    err = trp__json_hex(item, "memo", s->memo, TRP_MEMO_LEN);
    if (err == TRP_OK) s->has_memo = 1;
    return optional(err);
}

static trp_err_t read_details(const trp_json *details, trp_charge_request *r)
{
    trp_json v, item;
    size_t pos = 0, i;
    uint8_t split_total[32] = {0};
    int pull = 0;
    trp_err_t err;

    err = trp_json_get(details, "chainId", &v);
    if (err == TRP_OK) {
        if (trp_json_get_uint64(&v, &r->chain_id) != TRP_OK || r->chain_id == 0) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }

    err = trp_json_get(details, "feePayer", &v);
    if (err == TRP_OK) {
        if (trp_json_get_bool(&v, &r->fee_payer) != TRP_OK) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }

    err = trp__json_hex(details, "memo", r->memo, TRP_MEMO_LEN);
    if (err == TRP_OK) r->has_memo = 1;
    else if ((err = optional(err)) != TRP_OK) return err;

    err = trp_json_get(details, "supportedModes", &v);
    if (err == TRP_OK) {
        char mode[8];
        if (v.type != TRP_JSON_ARRAY) return TRP_ERR_INVALID;
        while ((err = trp_json_next(&v, &pos, &item)) == TRP_OK) {
            size_t n;
            if (item.type != TRP_JSON_STRING) return TRP_ERR_INVALID;
            if (trp_json_get_string(&item, mode, sizeof(mode), &n) == TRP_OK && n == 4 &&
                memcmp(mode, "pull", 4) == 0)
                pull = 1;
        }
        if (err != TRP_ERR_NOT_FOUND) return err;
        if (!pull) return TRP_ERR_UNSUPPORTED; /* push only */
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }

    err = trp_json_get(details, "splits", &v);
    if (err == TRP_ERR_NOT_FOUND) return TRP_OK;
    if (err != TRP_OK || v.type != TRP_JSON_ARRAY) return TRP_ERR_INVALID;
    pos = 0;
    while ((err = trp_json_next(&v, &pos, &item)) == TRP_OK) {
        if (r->split_count == TRP_MAX_SPLITS) return TRP_ERR_UNSUPPORTED;
        if ((err = read_split(&item, &r->splits[r->split_count])) != TRP_OK) return err;
        r->split_count++;
    }
    if (err != TRP_ERR_NOT_FOUND) return err;
    for (i = 0; i < r->split_count; i++)
        if (u256_add(split_total, r->splits[i].amount)) return TRP_ERR_INVALID;
    /* The primary recipient must keep a positive share. */
    if (r->split_count && u256_cmp(split_total, r->amount) >= 0) return TRP_ERR_INVALID;
    return TRP_OK;
}

trp_err_t trp_charge_request_parse(const trp_challenge *ch, trp_charge_request *r)
{
    const trp_json *req = &ch->request_json;
    trp_json details;
    trp_err_t err;

    memset(r, 0, sizeof(*r));
    r->chain_id = TRP_TEMPO_MODERATO; /* the spec's default */
    if (!trp__str_eq(ch->method, "tempo") || !trp__str_eq(ch->intent, "charge")) return TRP_ERR_UNSUPPORTED;
    if (req->type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;

    if (trp__json_u256(req, "amount", r->amount) != TRP_OK) return TRP_ERR_INVALID;
    if (trp__is_zero(r->amount, TRP_U256_LEN)) return TRP_ERR_UNSUPPORTED; /* proof credential */
    if (trp__json_hex(req, "currency", r->currency, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    if (trp__json_hex(req, "recipient", r->recipient, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    if (ch->expires.ptr && trp_parse_rfc3339(ch->expires.ptr, ch->expires.len, &r->expires) != TRP_OK)
        return TRP_ERR_INVALID;

    err = trp_json_get(req, "methodDetails", &details);
    if (err == TRP_ERR_NOT_FOUND) return TRP_OK;
    if (err != TRP_OK || details.type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;
    return read_details(&details, r);
}

/* ---- the policy ---------------------------------------------------------- */

static int listed(const uint8_t (*list)[TRP_ADDRESS_LEN], size_t count, const uint8_t address[TRP_ADDRESS_LEN])
{
    size_t i;

    if (count == 0) return 1;
    for (i = 0; i < count; i++)
        if (memcmp(list[i], address, TRP_ADDRESS_LEN) == 0) return 1;
    return 0;
}

trp_err_t trp_spend_policy_check(const trp_spend_policy *policy, const trp_charge_request *r)
{
    size_t i;
    int chain_ok;

    if (!policy || trp__is_zero(policy->max_amount, TRP_U256_LEN)) return TRP_ERR_INVALID;
    if (u256_cmp(r->amount, policy->max_amount) > 0) return TRP_ERR_DENIED;
    if (!listed(policy->tokens, policy->token_count, r->currency)) return TRP_ERR_DENIED;
    if (!listed(policy->recipients, policy->recipient_count, r->recipient)) return TRP_ERR_DENIED;
    for (i = 0; i < r->split_count; i++)
        if (!listed(policy->recipients, policy->recipient_count, r->splits[i].recipient)) return TRP_ERR_DENIED;
    chain_ok = policy->chain_id_count == 0;
    for (i = 0; i < policy->chain_id_count; i++)
        if (policy->chain_ids[i] == r->chain_id) chain_ok = 1;
    return chain_ok ? TRP_OK : TRP_ERR_DENIED;
}

/* ---- the charge ---------------------------------------------------------- */

trp_err_t trp_tempo_charge(const trp_challenge *ch, const trp_charge_options *opt, char *out,
                           size_t out_cap, uint8_t *work, size_t work_cap, trp_charge_result *result)
{
    trp_charge_request req;
    trp__carver c;
    uint8_t *calldata, *rlp_buf, *envelope;
    uint8_t primary[TRP_U256_LEN], tx_hash[32];
    char *payload_buf, *json_scratch, source[TRP__DID_MAX];
    size_t ncalls, rlp_cap, envelope_cap, payload_cap, envelope_len, i;
    uint64_t valid_before;
    trp_tempo_call calls[1 + TRP_MAX_SPLITS];
    trp_tempo_tx tx;
    trp_json_writer w;
    trp_err_t err;

    if (!ch || !opt || !opt->owner || !opt->signer || !opt->signer->sign_digest || !opt->policy ||
        opt->now == 0 || opt->now > UINT64_MAX - TRP_CHARGE_MAX_VALIDITY || opt->gas_limit == 0)
        return TRP_ERR_INVALID;
    if ((err = trp_charge_request_parse(ch, &req)) != TRP_OK) return err;
    if (!req.fee_payer && opt->max_fee_per_gas == 0) return TRP_ERR_INVALID;

    /* The server wrote the challenge: decide before anything is signed. */
    if ((err = trp_spend_policy_check(opt->policy, &req)) != TRP_OK) return err;
    if (opt->approve && opt->approve(opt->approve_ctx, ch, &req) != TRP_OK) return TRP_ERR_DENIED;

    if ((err = trp__valid_before(ch, opt->now, &valid_before)) != TRP_OK) return err;
    if (opt->valid_after >= valid_before) return TRP_ERR_INVALID;
    if (!req.has_memo) trp_mpp_attribution_memo(ch->realm, opt->client_id, ch->id, req.memo);

    /* Working space sized for this payment: a call is about 140 RLP bytes. */
    ncalls = 1 + req.split_count;
    rlp_cap = 160 + 140 * ncalls;
    envelope_cap = rlp_cap + 1 + TRP_ADDRESS_LEN + TRP_P256_SIGNATURE_LEN + 8;
    payload_cap = sizeof("{\"signature\":\"0x\",\"type\":\"transaction\"}") + 2 * envelope_cap;
    c.p = work;
    c.left = work_cap;
    calldata = (uint8_t *)trp__take(&c, ncalls * TRP_TRANSFER_WITH_MEMO_LEN);
    rlp_buf = (uint8_t *)trp__take(&c, rlp_cap);
    envelope = (uint8_t *)trp__take(&c, envelope_cap);
    payload_buf = (char *)trp__take(&c, payload_cap);
    if (!calldata || !rlp_buf || !envelope || !payload_buf) return TRP_ERR_BUFFER;
    json_scratch = (char *)c.p;

    /* The primary transfer carries the memo; each split carries its own, if any. */
    memcpy(primary, req.amount, TRP_U256_LEN);
    for (i = 0; i < req.split_count; i++) u256_sub(primary, req.splits[i].amount, primary);
    trp_tempo_transfer_with_memo(req.recipient, primary, req.memo, calldata);
    calls[0].to = req.currency;
    calls[0].data = calldata;
    calls[0].data_len = TRP_TRANSFER_WITH_MEMO_LEN;
    for (i = 0; i < req.split_count; i++) {
        const trp_charge_split *s = &req.splits[i];
        uint8_t *data = calldata + (i + 1) * TRP_TRANSFER_WITH_MEMO_LEN;
        if (s->has_memo) trp_tempo_transfer_with_memo(s->recipient, s->amount, s->memo, data);
        else trp_tempo_transfer(s->recipient, s->amount, data);
        calls[i + 1].to = req.currency;
        calls[i + 1].data = data;
        calls[i + 1].data_len = s->has_memo ? TRP_TRANSFER_WITH_MEMO_LEN : TRP_TRANSFER_LEN;
    }

    memset(&tx, 0, sizeof(tx));
    tx.chain_id = req.chain_id;
    tx.max_priority_fee_per_gas = opt->max_priority_fee_per_gas;
    tx.max_fee_per_gas = opt->max_fee_per_gas;
    tx.gas_limit = opt->gas_limit;
    tx.calls = calls;
    tx.call_count = ncalls;
    tx.valid_before = valid_before;
    tx.valid_after = opt->valid_after;
    tx.fee_payer = req.fee_payer;
    tx.fee_token = req.fee_payer ? NULL : opt->fee_token;

    if ((err = trp__keychain_sign_tx(&tx, opt->owner, opt->signer, rlp_buf, rlp_cap, envelope,
                                     envelope_cap, &envelope_len)) != TRP_OK)
        return err;
    trp_keccak256(envelope, envelope_len, tx_hash);

    /* {"signature":"0x76…","type":"transaction"}, keys in mppx's order. */
    trp_jw_init(&w, payload_buf, payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "signature");
    trp__jw_hex(&w, envelope, envelope_len);
    trp_jw_key(&w, "type");
    trp_jw_string(&w, "transaction", 11);
    trp_jw_object_end(&w);
    if ((err = trp_jw_finish(&w)) != TRP_OK) return err;

    trp__did_pkh(req.chain_id, opt->owner, source);
    if ((err = trp_credential_encode(ch, payload_buf, w.len, source, out, out_cap, json_scratch, c.left)) != TRP_OK)
        return err;
    if (result) {
        result->request = req;
        memcpy(result->tx_hash, tx_hash, 32);
    }
    return TRP_OK;
}

#include "transponder/session.h"

#include <string.h>

#include "transponder/credential.h"
#include "transponder/hex.h"
#include "transponder/json.h"
#include "transponder/keccak.h"
#include "internal.h"

const uint8_t TRP_CHANNEL_ESCROW[TRP_ADDRESS_LEN] = {0x4d, 0x50, 0x50};

#define DEFAULT_SESSION_CHAIN TRP_TEMPO_MAINNET /* the session spec's default */
#define OPEN_CALLDATA_LEN (4 + 6 * 32)
#define TOP_UP_CALLDATA_LEN (4 + 8 * 32)

/* ---- ABI words and hashing ------------------------------------------------ */

static void word_address(uint8_t w[32], const uint8_t a[TRP_ADDRESS_LEN])
{
    memset(w, 0, 12);
    memcpy(w + 12, a, TRP_ADDRESS_LEN);
}

static void word_u64(uint8_t w[32], uint64_t v)
{
    int i;
    memset(w, 0, 24);
    for (i = 0; i < 8; i++) w[31 - i] = (uint8_t)(v >> (8 * i));
}

static void hash_address(trp_keccak_ctx *c, const uint8_t a[TRP_ADDRESS_LEN])
{
    uint8_t w[32];
    word_address(w, a);
    trp_keccak256_update(c, w, 32);
}

static void hash_u64(trp_keccak_ctx *c, uint64_t v)
{
    uint8_t w[32];
    word_u64(w, v);
    trp_keccak256_update(c, w, 32);
}

static void keccak_text(const char *s, uint8_t out[32])
{
    trp_keccak256((const uint8_t *)s, strlen(s), out);
}

/* A uint96 has its top 160 bits clear. */
static int fits_u96(const uint8_t a[TRP_U256_LEN])
{
    return trp__is_zero(a, TRP_U256_LEN - 12);
}

void trp_channel_id(const trp_channel_descriptor *d, const uint8_t escrow[TRP_ADDRESS_LEN],
                    uint64_t chain_id, uint8_t out[32])
{
    trp_keccak_ctx c;

    trp_keccak256_init(&c);
    hash_address(&c, d->payer);
    hash_address(&c, d->payee);
    hash_address(&c, d->operator_);
    hash_address(&c, d->token);
    trp_keccak256_update(&c, d->salt, 32);
    hash_address(&c, d->authorized_signer);
    trp_keccak256_update(&c, d->expiring_nonce_hash, 32);
    hash_address(&c, escrow);
    hash_u64(&c, chain_id);
    trp_keccak256_final(&c, out);
}

static void domain_separator(uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN], uint8_t out[32])
{
    uint8_t h[32];
    trp_keccak_ctx c;

    trp_keccak256_init(&c);
    keccak_text("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", h);
    trp_keccak256_update(&c, h, 32);
    keccak_text("TIP20 Channel Reserve", h);
    trp_keccak256_update(&c, h, 32);
    keccak_text("1", h);
    trp_keccak256_update(&c, h, 32);
    hash_u64(&c, chain_id);
    hash_address(&c, escrow);
    trp_keccak256_final(&c, out);
}

static trp_err_t typed_digest(const char *type, uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN],
                              const uint8_t channel_id[32], const uint8_t amount[TRP_U256_LEN],
                              uint8_t out[32])
{
    static const uint8_t PREFIX[2] = {0x19, 0x01};
    uint8_t typehash[32], struct_hash[32], domain[32];
    trp_keccak_ctx c;

    if (!fits_u96(amount)) return TRP_ERR_INVALID;
    keccak_text(type, typehash);
    trp_keccak256_init(&c);
    trp_keccak256_update(&c, typehash, 32);
    trp_keccak256_update(&c, channel_id, 32);
    trp_keccak256_update(&c, amount, 32);
    trp_keccak256_final(&c, struct_hash);
    domain_separator(chain_id, escrow, domain);
    trp_keccak256_init(&c);
    trp_keccak256_update(&c, PREFIX, 2);
    trp_keccak256_update(&c, domain, 32);
    trp_keccak256_update(&c, struct_hash, 32);
    trp_keccak256_final(&c, out);
    return TRP_OK;
}

trp_err_t trp_voucher_digest(uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN],
                             const uint8_t channel_id[32], const uint8_t amount[TRP_U256_LEN],
                             uint8_t out[32])
{
    return typed_digest("Voucher(bytes32 channelId,uint96 cumulativeAmount)", chain_id, escrow,
                        channel_id, amount, out);
}

trp_err_t trp_close_authorization_digest(uint64_t chain_id, const uint8_t escrow[TRP_ADDRESS_LEN],
                                         const uint8_t channel_id[32],
                                         const uint8_t amount[TRP_U256_LEN], uint8_t out[32])
{
    return typed_digest("CloseAuthorization(bytes32 channelId,uint96 cumulativeAmount)", chain_id,
                        escrow, channel_id, amount, out);
}

/* open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner) */
static void open_calldata(const trp_channel_descriptor *d, const uint8_t deposit[TRP_U256_LEN],
                          uint8_t out[OPEN_CALLDATA_LEN])
{
    static const uint8_t SELECTOR[4] = {0xed, 0xc5, 0x3b, 0x00};

    memcpy(out, SELECTOR, 4);
    word_address(out + 4, d->payee);
    word_address(out + 36, d->operator_);
    word_address(out + 68, d->token);
    memcpy(out + 100, deposit, 32);
    memcpy(out + 132, d->salt, 32);
    word_address(out + 164, d->authorized_signer);
}

/* topUp((address,address,address,address,bytes32,address,bytes32) descriptor, uint96 additionalDeposit) */
static void top_up_calldata(const trp_channel_descriptor *d, const uint8_t additional[TRP_U256_LEN],
                            uint8_t out[TOP_UP_CALLDATA_LEN])
{
    static const uint8_t SELECTOR[4] = {0xdc, 0x48, 0x47, 0x1e};

    memcpy(out, SELECTOR, 4);
    word_address(out + 4, d->payer);
    word_address(out + 36, d->payee);
    word_address(out + 68, d->operator_);
    word_address(out + 100, d->token);
    memcpy(out + 132, d->salt, 32);
    word_address(out + 164, d->authorized_signer);
    memcpy(out + 196, d->expiring_nonce_hash, 32);
    memcpy(out + 228, additional, 32);
}

/* ---- the request ---------------------------------------------------------- */

trp_err_t trp_session_request_parse(const trp_challenge *ch, trp_session_request *r)
{
    const trp_json *req = &ch->request_json;
    trp_json details, v;
    char protocol[8];
    size_t n;
    trp_err_t err;

    memset(r, 0, sizeof(*r));
    r->chain_id = DEFAULT_SESSION_CHAIN;
    if (!trp__str_eq(ch->method, "tempo") || !trp__str_eq(ch->intent, "session")) return TRP_ERR_UNSUPPORTED;
    if (req->type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;

    if (trp__json_u256(req, "amount", r->price) != TRP_OK) return TRP_ERR_INVALID;
    err = trp__json_u256(req, "suggestedDeposit", r->suggested_deposit);
    if (err == TRP_OK) r->has_suggested_deposit = 1;
    else if (err != TRP_ERR_NOT_FOUND) return TRP_ERR_INVALID;
    if (trp__json_hex(req, "currency", r->currency, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    if (trp__json_hex(req, "recipient", r->recipient, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;
    if (ch->expires.ptr && trp_parse_rfc3339(ch->expires.ptr, ch->expires.len, &r->expires) != TRP_OK)
        return TRP_ERR_INVALID;

    /* methodDetails carries the escrow, which is required. */
    if (trp_json_get(req, "methodDetails", &details) != TRP_OK || details.type != TRP_JSON_OBJECT)
        return TRP_ERR_INVALID;
    err = trp__json_string(&details, "sessionProtocol", protocol, sizeof(protocol), &n);
    if (err == TRP_ERR_NOT_FOUND) return TRP_ERR_UNSUPPORTED; /* absent means v1 */
    if (err != TRP_OK) return TRP_ERR_INVALID;
    if (n != 2 || memcmp(protocol, "v2", 2) != 0) return TRP_ERR_UNSUPPORTED;
    if (trp__json_hex(&details, "escrowContract", r->escrow, TRP_ADDRESS_LEN) != TRP_OK) return TRP_ERR_INVALID;

    err = trp_json_get(&details, "chainId", &v);
    if (err == TRP_OK) {
        if (trp_json_get_uint64(&v, &r->chain_id) != TRP_OK || r->chain_id == 0) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }
    err = trp__json_hex(&details, "operator", r->operator_, TRP_ADDRESS_LEN);
    if (err != TRP_OK && err != TRP_ERR_NOT_FOUND) return TRP_ERR_INVALID;
    err = trp_json_get(&details, "feePayer", &v);
    if (err == TRP_OK) {
        if (trp_json_get_bool(&v, &r->fee_payer) != TRP_OK) return TRP_ERR_INVALID;
    } else if (err != TRP_ERR_NOT_FOUND) {
        return err;
    }
    err = trp__json_u256(&details, "minVoucherDelta", r->min_voucher_delta);
    if (err == TRP_OK) r->has_min_voucher_delta = 1;
    else if (err != TRP_ERR_NOT_FOUND) return TRP_ERR_INVALID;
    return TRP_OK;
}

/*
 * Decide on locking funds in the channel before anything is signed. The
 * policy speaks in charge terms (an amount to a recipient, in a token, on a
 * chain) and limits the channel's whole deposit, `channel_total`; approve
 * sees the amount this call adds.
 */
static trp_err_t decide(const trp_charge_options *opt, const trp_challenge *ch, const trp_session_request *r,
                        const uint8_t channel_total[TRP_U256_LEN], const uint8_t amount[TRP_U256_LEN])
{
    trp_charge_request as_charge;
    trp_err_t err;

    memset(&as_charge, 0, sizeof(as_charge));
    memcpy(as_charge.amount, channel_total, TRP_U256_LEN);
    memcpy(as_charge.currency, r->currency, TRP_ADDRESS_LEN);
    memcpy(as_charge.recipient, r->recipient, TRP_ADDRESS_LEN);
    as_charge.chain_id = r->chain_id;
    as_charge.fee_payer = r->fee_payer;
    as_charge.expires = r->expires;
    if ((err = trp_spend_policy_check(opt->policy, &as_charge)) != TRP_OK) return err;
    memcpy(as_charge.amount, amount, TRP_U256_LEN);
    if (opt->approve && opt->approve(opt->approve_ctx, ch, &as_charge) != TRP_OK) return TRP_ERR_DENIED;
    return TRP_OK;
}

/* Only the channel's own key can sign its vouchers. */
static int is_channel_signer(const trp_session *s, const trp_signer *signer)
{
    uint8_t address[TRP_ADDRESS_LEN];

    trp_p256_address(signer->public_key, address);
    return memcmp(address, s->descriptor.authorized_signer, TRP_ADDRESS_LEN) == 0;
}

/* ---- credentials ---------------------------------------------------------- */

static void jw_descriptor(trp_json_writer *w, const trp_channel_descriptor *d)
{
    trp_jw_object_begin(w);
    trp_jw_key(w, "authorizedSigner");
    trp__jw_address(w, d->authorized_signer);
    trp_jw_key(w, "expiringNonceHash");
    trp__jw_hex(w, d->expiring_nonce_hash, 32);
    trp_jw_key(w, "operator");
    trp__jw_address(w, d->operator_);
    trp_jw_key(w, "payee");
    trp__jw_address(w, d->payee);
    trp_jw_key(w, "payer");
    trp__jw_address(w, d->payer);
    trp_jw_key(w, "salt");
    trp__jw_hex(w, d->salt, 32);
    trp_jw_key(w, "token");
    trp__jw_address(w, d->token);
    trp_jw_object_end(w);
}

/* Room for one transaction: its RLP, its envelope and the payload JSON around them. */
typedef struct {
    uint8_t *calldata, *rlp, *envelope;
    char *payload, *scratch;
    size_t rlp_cap, envelope_cap, payload_cap, scratch_cap;
} buffers;

static trp_err_t carve(uint8_t *work, size_t work_cap, size_t calldata_len, buffers *b)
{
    trp__carver c;

    b->rlp_cap = 200 + calldata_len;
    b->envelope_cap = b->rlp_cap + 1 + TRP_ADDRESS_LEN + TRP_P256_SIGNATURE_LEN + 8;
    b->payload_cap = 2 * b->envelope_cap + 2 * TRP_P256_SIGNATURE_LEN + 1024; /* hex, signatures, descriptor */
    c.p = work;
    c.left = work_cap;
    b->calldata = (uint8_t *)trp__take(&c, calldata_len ? calldata_len : 1);
    b->rlp = (uint8_t *)trp__take(&c, b->rlp_cap);
    b->envelope = (uint8_t *)trp__take(&c, b->envelope_cap);
    b->payload = (char *)trp__take(&c, b->payload_cap);
    if (!b->calldata || !b->rlp || !b->envelope || !b->payload) return TRP_ERR_BUFFER;
    b->scratch = (char *)c.p;
    b->scratch_cap = c.left;
    return TRP_OK;
}

static trp_err_t finish(const trp_challenge *ch, const trp_session *s, trp_json_writer *w,
                        buffers *b, char *out, size_t out_cap)
{
    char source[TRP__DID_MAX];
    trp_err_t err;

    if ((err = trp_jw_finish(w)) != TRP_OK) return err;
    trp__did_pkh(s->chain_id, s->descriptor.payer, source);
    return trp_credential_encode(ch, b->payload, w->len, source, out, out_cap, b->scratch, b->scratch_cap);
}

static trp_err_t check_options(const trp_charge_options *opt)
{
    if (!opt || !opt->owner || !opt->signer || !opt->signer->sign_digest || !opt->policy ||
        opt->now == 0 || opt->now > UINT64_MAX - TRP_CHARGE_MAX_VALIDITY || opt->gas_limit == 0)
        return TRP_ERR_INVALID;
    return TRP_OK;
}

/* A transaction with one call into the escrow, signed by the access key. */
static trp_err_t sign_escrow_call(const trp_challenge *ch, const trp_charge_options *opt,
                                  const trp_session_request *r, const uint8_t fee_token[TRP_ADDRESS_LEN],
                                  const uint8_t *calldata, size_t calldata_len, buffers *b,
                                  trp_tempo_tx *tx, trp_tempo_call *call, size_t *envelope_len)
{
    uint64_t valid_before;
    trp_err_t err;

    /* Sponsored or not, the transaction declares its fees (mppx's sponsor rejects 0). */
    if (opt->max_fee_per_gas == 0 || opt->max_priority_fee_per_gas > opt->max_fee_per_gas) return TRP_ERR_INVALID;
    if ((err = trp__valid_before(ch, opt->now, &valid_before)) != TRP_OK) return err;
    if (opt->valid_after >= valid_before) return TRP_ERR_INVALID;

    call->to = r->escrow;
    call->data = calldata;
    call->data_len = calldata_len;
    memset(tx, 0, sizeof(*tx));
    tx->chain_id = r->chain_id;
    tx->max_priority_fee_per_gas = opt->max_priority_fee_per_gas;
    tx->max_fee_per_gas = opt->max_fee_per_gas;
    tx->gas_limit = opt->gas_limit;
    tx->calls = call;
    tx->call_count = 1;
    tx->valid_before = valid_before;
    tx->valid_after = opt->valid_after;
    tx->fee_payer = r->fee_payer;
    /* Like mppx, channel transactions pay their fee in the channel's token by default. */
    tx->fee_token = r->fee_payer ? NULL : (opt->fee_token ? opt->fee_token : fee_token);
    return trp__keychain_sign_tx(tx, opt->owner, opt->signer, b->rlp, b->rlp_cap, b->envelope,
                                 b->envelope_cap, envelope_len);
}

/* A session challenge for the same channel terms as `s`. */
static trp_err_t match_challenge(const trp_challenge *ch, const trp_session *s, trp_session_request *r)
{
    trp_err_t err = trp_session_request_parse(ch, r);

    if (err != TRP_OK) return err;
    if (r->chain_id != s->chain_id || memcmp(r->escrow, s->escrow, TRP_ADDRESS_LEN) != 0 ||
        memcmp(r->currency, s->descriptor.token, TRP_ADDRESS_LEN) != 0 ||
        memcmp(r->recipient, s->descriptor.payee, TRP_ADDRESS_LEN) != 0)
        return TRP_ERR_INVALID;
    return TRP_OK;
}

/* ---- actions --------------------------------------------------------------- */

trp_err_t trp_session_open(const trp_challenge *ch, const trp_charge_options *opt,
                           const uint8_t deposit[TRP_U256_LEN], const uint8_t salt[32],
                           trp_session *s, char *out, size_t out_cap, uint8_t *work, size_t work_cap)
{
    trp_session_request r;
    trp_session next;
    buffers b;
    trp_tempo_tx tx;
    trp_tempo_call call;
    trp_json_writer w;
    uint8_t digest[32], voucher[TRP_P256_SIGNATURE_LEN];
    size_t envelope_len;
    trp_err_t err;

    if (!ch || !s || (err = check_options(opt)) != TRP_OK) return TRP_ERR_INVALID;
    if ((err = trp_session_request_parse(ch, &r)) != TRP_OK) return err;
    /* Only the precompile escrow: a server cannot route the deposit elsewhere. */
    if (memcmp(r.escrow, TRP_CHANNEL_ESCROW, TRP_ADDRESS_LEN) != 0) return TRP_ERR_UNSUPPORTED;
    if (trp__is_zero(deposit, TRP_U256_LEN) || !fits_u96(deposit) || memcmp(deposit, r.price, 32) < 0)
        return TRP_ERR_INVALID;
    if ((err = decide(opt, ch, &r, deposit, deposit)) != TRP_OK) return err;
    if ((err = carve(work, work_cap, OPEN_CALLDATA_LEN, &b)) != TRP_OK) return err;

    memset(&next, 0, sizeof(next));
    memcpy(next.descriptor.payer, opt->owner, TRP_ADDRESS_LEN);
    memcpy(next.descriptor.payee, r.recipient, TRP_ADDRESS_LEN);
    memcpy(next.descriptor.operator_, r.operator_, TRP_ADDRESS_LEN);
    memcpy(next.descriptor.token, r.currency, TRP_ADDRESS_LEN);
    memcpy(next.descriptor.salt, salt, 32);
    trp_p256_address(opt->signer->public_key, next.descriptor.authorized_signer);
    memcpy(next.escrow, r.escrow, TRP_ADDRESS_LEN);
    next.chain_id = r.chain_id;
    memcpy(next.deposit, deposit, TRP_U256_LEN);

    open_calldata(&next.descriptor, deposit, b.calldata);
    if ((err = sign_escrow_call(ch, opt, &r, r.currency, b.calldata, OPEN_CALLDATA_LEN, &b, &tx, &call,
                                &envelope_len)) != TRP_OK)
        return err;
    /* The channel ID commits to the open transaction through its expiring-nonce hash. */
    if ((err = trp_tempo_expiring_nonce_hash(&tx, opt->owner, b.rlp, b.rlp_cap,
                                             next.descriptor.expiring_nonce_hash)) != TRP_OK)
        return err;
    trp_channel_id(&next.descriptor, next.escrow, next.chain_id, next.channel_id);

    /* The open pays for the request that carries it: its voucher covers one unit, as mppx's does. */
    memcpy(next.cumulative, r.price, TRP_U256_LEN);
    if ((err = trp_voucher_digest(next.chain_id, next.escrow, next.channel_id, next.cumulative, digest)) != TRP_OK)
        return err;
    if ((err = trp__sign_p256(opt->signer, digest, voucher)) != TRP_OK) return err;

    /* Fields in mppx's order. */
    trp_jw_init(&w, b.payload, b.payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "action");
    trp_jw_string(&w, "open", 4);
    trp_jw_key(&w, "type");
    trp_jw_string(&w, "transaction", 11);
    trp_jw_key(&w, "channelId");
    trp__jw_hex(&w, next.channel_id, 32);
    trp_jw_key(&w, "transaction");
    trp__jw_hex(&w, b.envelope, envelope_len);
    trp_jw_key(&w, "signature");
    trp__jw_hex(&w, voucher, sizeof(voucher));
    trp_jw_key(&w, "descriptor");
    jw_descriptor(&w, &next.descriptor);
    trp_jw_key(&w, "cumulativeAmount");
    trp__jw_decimal(&w, next.cumulative);
    trp_jw_key(&w, "authorizedSigner");
    trp__jw_address(&w, next.descriptor.authorized_signer);
    trp_jw_object_end(&w);
    if ((err = finish(ch, &next, &w, &b, out, out_cap)) != TRP_OK) return err;
    next.tx_valid_before = tx.valid_before;
    *s = next;
    return TRP_OK;
}

trp_err_t trp_session_voucher(trp_session *s, const trp_challenge *ch, const trp_signer *signer,
                              const uint8_t cumulative[TRP_U256_LEN], char *out, size_t out_cap,
                              uint8_t *work, size_t work_cap)
{
    trp_session_request r;
    buffers b;
    trp_json_writer w;
    uint8_t digest[32], voucher[TRP_P256_SIGNATURE_LEN];
    trp_err_t err;

    if (!s || !ch || !signer || !signer->sign_digest || s->closed || !is_channel_signer(s, signer))
        return TRP_ERR_INVALID;
    if ((err = match_challenge(ch, s, &r)) != TRP_OK) return err;
    /* Cumulative: never down, never past what is confirmed on deposit. */
    if (memcmp(cumulative, s->cumulative, 32) < 0 || memcmp(cumulative, s->deposit, 32) > 0) return TRP_ERR_INVALID;
    /* A raise smaller than the server's minimum would only be refused. */
    if (r.has_min_voucher_delta && memcmp(cumulative, s->cumulative, 32) != 0) {
        uint8_t delta[TRP_U256_LEN];
        unsigned borrow = 0;
        int i;
        for (i = 31; i >= 0; i--) {
            unsigned d = (unsigned)cumulative[i] - s->cumulative[i] - borrow;
            delta[i] = (uint8_t)d;
            borrow = (d >> 8) & 1;
        }
        if (memcmp(delta, r.min_voucher_delta, 32) < 0) return TRP_ERR_INVALID;
    }
    if ((err = carve(work, work_cap, 0, &b)) != TRP_OK) return err;
    if ((err = trp_voucher_digest(s->chain_id, s->escrow, s->channel_id, cumulative, digest)) != TRP_OK) return err;
    if ((err = trp__sign_p256(signer, digest, voucher)) != TRP_OK) return err;

    trp_jw_init(&w, b.payload, b.payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "action");
    trp_jw_string(&w, "voucher", 7);
    trp_jw_key(&w, "channelId");
    trp__jw_hex(&w, s->channel_id, 32);
    trp_jw_key(&w, "descriptor");
    jw_descriptor(&w, &s->descriptor);
    trp_jw_key(&w, "cumulativeAmount");
    trp__jw_decimal(&w, cumulative);
    trp_jw_key(&w, "signature");
    trp__jw_hex(&w, voucher, sizeof(voucher));
    trp_jw_object_end(&w);
    if ((err = finish(ch, s, &w, &b, out, out_cap)) != TRP_OK) return err;
    memcpy(s->cumulative, cumulative, TRP_U256_LEN);
    return TRP_OK;
}

trp_err_t trp_session_top_up(trp_session *s, const trp_challenge *ch, const trp_charge_options *opt,
                             const uint8_t additional[TRP_U256_LEN], char *out, size_t out_cap,
                             uint8_t *work, size_t work_cap)
{
    trp_session_request r;
    buffers b;
    trp_tempo_tx tx;
    trp_tempo_call call;
    trp_json_writer w;
    uint8_t total[TRP_U256_LEN];
    size_t envelope_len;
    unsigned carry = 0;
    int i;
    trp_err_t err;

    if (!s || !ch || (err = check_options(opt)) != TRP_OK) return TRP_ERR_INVALID;
    if (s->closed || !trp__is_zero(s->pending_top_up, TRP_U256_LEN)) return TRP_ERR_INVALID; /* one at a time */
    if (memcmp(opt->owner, s->descriptor.payer, TRP_ADDRESS_LEN) != 0) return TRP_ERR_INVALID;
    if ((err = match_challenge(ch, s, &r)) != TRP_OK) return err;
    for (i = 31; i >= 0; i--) {
        unsigned v = (unsigned)s->deposit[i] + additional[i] + carry;
        total[i] = (uint8_t)v;
        carry = v >> 8;
    }
    if (trp__is_zero(additional, TRP_U256_LEN) || carry || !fits_u96(total)) return TRP_ERR_INVALID;
    if ((err = decide(opt, ch, &r, total, additional)) != TRP_OK) return err;
    if ((err = carve(work, work_cap, TOP_UP_CALLDATA_LEN, &b)) != TRP_OK) return err;

    top_up_calldata(&s->descriptor, additional, b.calldata);
    if ((err = sign_escrow_call(ch, opt, &r, s->descriptor.token, b.calldata, TOP_UP_CALLDATA_LEN, &b, &tx,
                                &call, &envelope_len)) != TRP_OK)
        return err;

    trp_jw_init(&w, b.payload, b.payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "action");
    trp_jw_string(&w, "topUp", 5);
    trp_jw_key(&w, "type");
    trp_jw_string(&w, "transaction", 11);
    trp_jw_key(&w, "channelId");
    trp__jw_hex(&w, s->channel_id, 32);
    trp_jw_key(&w, "transaction");
    trp__jw_hex(&w, b.envelope, envelope_len);
    trp_jw_key(&w, "descriptor");
    jw_descriptor(&w, &s->descriptor);
    trp_jw_key(&w, "additionalDeposit");
    trp__jw_decimal(&w, additional);
    trp_jw_object_end(&w);
    if ((err = finish(ch, s, &w, &b, out, out_cap)) != TRP_OK) return err;
    /* Counted once the server has accepted it: see trp_session_top_up_confirmed. */
    memcpy(s->pending_top_up, additional, TRP_U256_LEN);
    s->tx_valid_before = tx.valid_before;
    return TRP_OK;
}

void trp_session_top_up_confirmed(trp_session *s)
{
    unsigned carry = 0;
    int i;

    for (i = 31; i >= 0; i--) {
        unsigned v = (unsigned)s->deposit[i] + s->pending_top_up[i] + carry;
        s->deposit[i] = (uint8_t)v;
        carry = v >> 8;
    }
    memset(s->pending_top_up, 0, TRP_U256_LEN);
}

void trp_session_top_up_failed(trp_session *s)
{
    memset(s->pending_top_up, 0, TRP_U256_LEN);
}

trp_err_t trp_session_close(trp_session *s, const trp_challenge *ch, const trp_signer *signer, char *out,
                            size_t out_cap, uint8_t *work, size_t work_cap)
{
    trp_session_request r;
    buffers b;
    trp_json_writer w;
    uint8_t digest[32], voucher[TRP_P256_SIGNATURE_LEN], close_sig[TRP_P256_SIGNATURE_LEN];
    trp_err_t err;

    if (!s || !ch || !signer || !signer->sign_digest || !is_channel_signer(s, signer)) return TRP_ERR_INVALID;
    if ((err = match_challenge(ch, s, &r)) != TRP_OK) return err;
    if ((err = carve(work, work_cap, 0, &b)) != TRP_OK) return err;
    if ((err = trp_voucher_digest(s->chain_id, s->escrow, s->channel_id, s->cumulative, digest)) != TRP_OK) return err;
    if ((err = trp__sign_p256(signer, digest, voucher)) != TRP_OK) return err;
    if ((err = trp_close_authorization_digest(s->chain_id, s->escrow, s->channel_id, s->cumulative, digest)) != TRP_OK)
        return err;
    if ((err = trp__sign_p256(signer, digest, close_sig)) != TRP_OK) return err;

    trp_jw_init(&w, b.payload, b.payload_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "action");
    trp_jw_string(&w, "close", 5);
    trp_jw_key(&w, "channelId");
    trp__jw_hex(&w, s->channel_id, 32);
    trp_jw_key(&w, "descriptor");
    jw_descriptor(&w, &s->descriptor);
    trp_jw_key(&w, "cumulativeAmount");
    trp__jw_decimal(&w, s->cumulative);
    trp_jw_key(&w, "signature");
    trp__jw_hex(&w, voucher, sizeof(voucher));
    trp_jw_key(&w, "closeSignature");
    trp__jw_hex(&w, close_sig, sizeof(close_sig));
    trp_jw_object_end(&w);
    if ((err = finish(ch, s, &w, &b, out, out_cap)) != TRP_OK) return err;
    s->closed = 1; /* no more vouchers; closing again is allowed */
    return TRP_OK;
}

/* ---- keeping a session across restarts ------------------------------------ */

#define STATE_VERSION 1
#define STATE_CHECKSUM_LEN 4

static uint8_t *put(uint8_t *p, const uint8_t *src, size_t n)
{
    memcpy(p, src, n);
    return p + n;
}

static const uint8_t *get(const uint8_t *p, uint8_t *dst, size_t n)
{
    memcpy(dst, p, n);
    return p + n;
}

static uint8_t *put_u64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
    return p + 8;
}

static const uint8_t *get_u64(const uint8_t *p, uint64_t *v)
{
    int i;
    *v = 0;
    for (i = 0; i < 8; i++) *v = (*v << 8) | p[i];
    return p + 8;
}

void trp_session_save(const trp_session *s, uint8_t out[TRP_SESSION_STATE_LEN])
{
    const trp_channel_descriptor *d = &s->descriptor;
    uint8_t *p = out, sum[32];

    p = put(p, (const uint8_t *)"TRPS", 4);
    *p++ = STATE_VERSION;
    p = put_u64(p, s->chain_id);
    p = put(p, s->escrow, TRP_ADDRESS_LEN);
    p = put(p, d->payer, TRP_ADDRESS_LEN);
    p = put(p, d->payee, TRP_ADDRESS_LEN);
    p = put(p, d->operator_, TRP_ADDRESS_LEN);
    p = put(p, d->token, TRP_ADDRESS_LEN);
    p = put(p, d->salt, 32);
    p = put(p, d->authorized_signer, TRP_ADDRESS_LEN);
    p = put(p, d->expiring_nonce_hash, 32);
    p = put(p, s->channel_id, 32);
    p = put(p, s->deposit, TRP_U256_LEN);
    p = put(p, s->pending_top_up, TRP_U256_LEN);
    p = put(p, s->cumulative, TRP_U256_LEN);
    *p++ = s->closed ? 1 : 0;
    p = put_u64(p, s->tx_valid_before);
    trp_keccak256(out, (size_t)(p - out), sum);
    memcpy(p, sum, STATE_CHECKSUM_LEN);
}

trp_err_t trp_session_load(trp_session *s, const uint8_t *in, size_t len)
{
    trp_session next;
    trp_channel_descriptor *d = &next.descriptor;
    const uint8_t *p = in;
    uint8_t sum[32], id[32];

    if (!s || !in || len != TRP_SESSION_STATE_LEN) return TRP_ERR_INVALID;
    trp_keccak256(in, len - STATE_CHECKSUM_LEN, sum);
    if (memcmp(in + len - STATE_CHECKSUM_LEN, sum, STATE_CHECKSUM_LEN) != 0) return TRP_ERR_INVALID;
    if (memcmp(p, "TRPS", 4) != 0 || p[4] != STATE_VERSION) return TRP_ERR_INVALID;
    p += 5;

    memset(&next, 0, sizeof(next));
    p = get_u64(p, &next.chain_id);
    p = get(p, next.escrow, TRP_ADDRESS_LEN);
    p = get(p, d->payer, TRP_ADDRESS_LEN);
    p = get(p, d->payee, TRP_ADDRESS_LEN);
    p = get(p, d->operator_, TRP_ADDRESS_LEN);
    p = get(p, d->token, TRP_ADDRESS_LEN);
    p = get(p, d->salt, 32);
    p = get(p, d->authorized_signer, TRP_ADDRESS_LEN);
    p = get(p, d->expiring_nonce_hash, 32);
    p = get(p, next.channel_id, 32);
    p = get(p, next.deposit, TRP_U256_LEN);
    p = get(p, next.pending_top_up, TRP_U256_LEN);
    p = get(p, next.cumulative, TRP_U256_LEN);
    if (*p > 1) return TRP_ERR_INVALID;
    next.closed = *p++;
    get_u64(p, &next.tx_valid_before);

    /* Only what open could have produced. */
    trp_channel_id(d, next.escrow, next.chain_id, id);
    if (memcmp(id, next.channel_id, 32) != 0 || !fits_u96(next.deposit) || !fits_u96(next.pending_top_up) ||
        memcmp(next.cumulative, next.deposit, 32) > 0)
        return TRP_ERR_INVALID;
    *s = next;
    return TRP_OK;
}

/* getChannelState(bytes32) -> (uint96 settled, uint96 deposit, uint32 closeRequestedAt) */
#define STATE_RESULT_LEN (3 * 32)

trp_err_t trp_session_state_request(const trp_session *s, char *out, size_t out_cap)
{
    static const char head[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"";
    static const char mid[] = "\",\"data\":\"";
    static const char tail[] = "\"},\"latest\"]}";
    uint8_t calldata[4 + 32], selector[32];
    char *p = out;

    if (!s || !out) return TRP_ERR_INVALID;
    if (out_cap < sizeof(head) - 1 + 42 + sizeof(mid) - 1 + 2 + 2 * sizeof(calldata) + sizeof(tail))
        return TRP_ERR_BUFFER;
    keccak_text("getChannelState(bytes32)", selector);
    memcpy(calldata, selector, 4);
    memcpy(calldata + 4, s->channel_id, 32);

    memcpy(p, head, sizeof(head) - 1);
    p += sizeof(head) - 1;
    trp_hex_encode(s->escrow, TRP_ADDRESS_LEN, 1, p, 43);
    p += 42;
    memcpy(p, mid, sizeof(mid) - 1);
    p += sizeof(mid) - 1;
    trp_hex_encode(calldata, sizeof(calldata), 1, p, 2 + 2 * sizeof(calldata) + 1);
    p += 2 + 2 * sizeof(calldata);
    memcpy(p, tail, sizeof(tail)); /* with its NUL */
    return TRP_OK;
}

/* A word that holds an unsigned integer of `bits` bits. */
static int word_fits(const uint8_t w[32], int bits)
{
    return trp__is_zero(w, (size_t)(32 - bits / 8));
}

static void add_u256(const uint8_t a[32], const uint8_t b[32], uint8_t out[32], unsigned *carry_out)
{
    unsigned carry = 0;
    int i;
    for (i = 31; i >= 0; i--) {
        unsigned v = (unsigned)a[i] + b[i] + carry;
        out[i] = (uint8_t)v;
        carry = v >> 8;
    }
    *carry_out = carry;
}

trp_err_t trp_session_sync(trp_session *s, const char *response, size_t len, uint64_t now)
{
    trp_json root, result;
    char hex[2 + 2 * STATE_RESULT_LEN + 1];
    uint8_t state[STATE_RESULT_LEN], expected[32];
    const uint8_t *settled = state, *deposit = state + 32, *close_requested = state + 64;
    size_t hex_len, got;
    unsigned carry;
    int in_flight;

    if (!s || !response) return TRP_ERR_INVALID;
    if (trp_json_parse(response, len, &root) != TRP_OK || root.type != TRP_JSON_OBJECT ||
        trp_json_get(&root, "result", &result) != TRP_OK ||
        trp_json_get_string(&result, hex, sizeof(hex), &hex_len) != TRP_OK || hex_len != sizeof(hex) - 1 ||
        hex[0] != '0' || (hex[1] != 'x' && hex[1] != 'X') ||
        trp_hex_decode(hex, hex_len, state, sizeof(state), &got) != TRP_OK || got != sizeof(state))
        return TRP_ERR_INVALID;
    if (!word_fits(settled, 96) || !word_fits(deposit, 96) || !word_fits(close_requested, 32))
        return TRP_ERR_INVALID;

    /* Could the last open or top-up still land? Then the chain is not the last word yet. */
    in_flight = s->tx_valid_before != 0 && now <= s->tx_valid_before + TRP_SESSION_SYNC_MARGIN;
    add_u256(s->deposit, s->pending_top_up, expected, &carry);

    if (trp__is_zero(deposit, 32)) {
        /* Closed, or the open has not landed. */
        if (in_flight && !s->closed) return TRP_ERR_PENDING;
        s->closed = 1;
        memset(s->pending_top_up, 0, TRP_U256_LEN);
        return TRP_OK;
    }
    if (!trp__is_zero(s->pending_top_up, TRP_U256_LEN) && memcmp(deposit, expected, 32) < 0 && in_flight)
        return TRP_ERR_PENDING;

    memcpy(s->deposit, deposit, TRP_U256_LEN);
    memset(s->pending_top_up, 0, TRP_U256_LEN);
    if (memcmp(settled, s->cumulative, 32) > 0) memcpy(s->cumulative, settled, TRP_U256_LEN);
    if (!trp__is_zero(close_requested, 32) || memcmp(s->cumulative, s->deposit, 32) > 0) s->closed = 1;
    return TRP_OK;
}

#include "transponder/receipt.h"

#include "transponder/base64url.h"
#include "transponder/charge.h"
#include "transponder/hex.h"

#include <string.h>

static trp_err_t take_string(const trp_json *obj, const char *key, char **cursor, size_t *left,
                             trp_str *out)
{
    trp_json v;
    size_t n;
    trp_err_t err = trp_json_get(obj, key, &v);

    if (err == TRP_ERR_NOT_FOUND) return TRP_ERR_INVALID; /* every field here is required */
    if (err != TRP_OK) return err;
    if (v.type != TRP_JSON_STRING) return TRP_ERR_INVALID;
    if ((err = trp_json_get_string(&v, *cursor, *left, &n)) != TRP_OK) return err;
    out->ptr = *cursor;
    out->len = n;
    *cursor += n + 1;
    *left -= n + 1;
    return TRP_OK;
}

trp_err_t trp_receipt_parse(const char *value, size_t len, trp_receipt *out, char *scratch,
                            size_t scratch_cap)
{
    size_t decoded_len;
    char *cursor;
    size_t left;
    uint64_t when;
    trp_err_t err;

    while (len && (*value == ' ' || *value == '\t')) value++, len--;
    while (len && (value[len - 1] == ' ' || value[len - 1] == '\t' || value[len - 1] == '\r' ||
                   value[len - 1] == '\n'))
        len--;
    if (len == 0) return TRP_ERR_INVALID;

    if ((err = trp_base64url_decode(value, len, (uint8_t *)scratch, scratch_cap, &decoded_len)) != TRP_OK)
        return err;
    if (!trp_utf8_valid((const uint8_t *)scratch, decoded_len)) return TRP_ERR_INVALID;
    if ((err = trp_json_parse(scratch, decoded_len, &out->json)) != TRP_OK) return err;
    if (out->json.type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;

    cursor = scratch + decoded_len;
    left = scratch_cap - decoded_len;
    if ((err = take_string(&out->json, "status", &cursor, &left, &out->status)) != TRP_OK ||
        (err = take_string(&out->json, "method", &cursor, &left, &out->method)) != TRP_OK ||
        (err = take_string(&out->json, "timestamp", &cursor, &left, &out->timestamp)) != TRP_OK ||
        (err = take_string(&out->json, "reference", &cursor, &left, &out->reference)) != TRP_OK)
        return err;
    if (trp_parse_rfc3339(out->timestamp.ptr, out->timestamp.len, &when) != TRP_OK) return TRP_ERR_INVALID;
    return TRP_OK;
}

static int str_is(trp_str s, const char *lit)
{
    return s.len == strlen(lit) && memcmp(s.ptr, lit, s.len) == 0;
}

trp_err_t trp_receipt_verify(const trp_receipt *receipt, const char *method, const uint8_t *tx_hash)
{
    uint8_t reference[32];
    size_t n = 0;

    if (!str_is(receipt->status, "success")) return TRP_ERR_DENIED;
    if (method && !str_is(receipt->method, method)) return TRP_ERR_DENIED;
    if (!tx_hash) return TRP_OK;
    if (receipt->reference.len != 66 ||
        trp_hex_decode(receipt->reference.ptr, receipt->reference.len, reference, sizeof(reference), &n) != TRP_OK ||
        n != 32 || memcmp(reference, tx_hash, 32) != 0)
        return TRP_ERR_DENIED;
    return TRP_OK;
}

#include "transponder/credential.h"

#include <string.h>

#include "transponder/base64url.h"

static void put_field(trp_json_writer *w, const char *key, trp_str value)
{
    if (!value.ptr) return;
    trp_jw_key(w, key);
    trp_jw_string(w, value.ptr, value.len);
}

trp_err_t trp_credential_encode(const trp_challenge *ch, const char *payload_json,
                                size_t payload_len, const char *source, char *out,
                                size_t out_cap, char *scratch, size_t scratch_cap)
{
    static const char PREFIX[] = "Payment ";
    const size_t prefix_len = sizeof(PREFIX) - 1;
    trp_json_writer w;
    trp_json payload;
    trp_err_t err;

    if (!ch->id.ptr || ch->id.len == 0 || !ch->request.ptr) return TRP_ERR_INVALID;
    if ((err = trp_json_parse(payload_json, payload_len, &payload)) != TRP_OK) return err;
    if (payload.type != TRP_JSON_OBJECT) return TRP_ERR_INVALID;

    trp_jw_init(&w, scratch, scratch_cap);
    trp_jw_object_begin(&w);
    trp_jw_key(&w, "challenge");
    trp_jw_object_begin(&w);
    put_field(&w, "id", ch->id);
    put_field(&w, "realm", ch->realm);
    put_field(&w, "method", ch->method);
    put_field(&w, "intent", ch->intent);
    put_field(&w, "description", ch->description);
    put_field(&w, "digest", ch->digest);
    put_field(&w, "expires", ch->expires);
    put_field(&w, "header", ch->header);
    put_field(&w, "opaque", ch->opaque);
    put_field(&w, "request", ch->request);
    trp_jw_object_end(&w);
    trp_jw_key(&w, "payload");
    trp_jw_raw(&w, payload.ptr, payload.len);
    if (source) {
        trp_jw_key(&w, "source");
        trp_jw_string(&w, source, strlen(source));
    }
    trp_jw_object_end(&w);
    if ((err = trp_jw_finish(&w)) != TRP_OK) return err;

    if (out_cap < prefix_len + TRP_BASE64URL_ENCODED_LEN(w.len) + 1) return TRP_ERR_BUFFER;
    memcpy(out, PREFIX, prefix_len);
    return trp_base64url_encode((const uint8_t *)scratch, w.len, out + prefix_len,
                                out_cap - prefix_len);
}

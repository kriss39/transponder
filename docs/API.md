# Using Transponder

Transponder answers MPP `402 Payment Required` challenges from C. It does no networking itself. You make the HTTP requests; Transponder reads the challenge, checks it against the device's limits, signs, and writes the header value to send back. This page shows the calls in the order a device makes them. The headers in [`include/transponder`](../include/transponder) document every function in full.

- [Add it to a build](#add-it-to-a-build)
- [The signer](#the-signer)
- [Authorize the device key](#authorize-the-device-key)
- [Pay a charge](#pay-a-charge)
- [Pay with a session](#pay-with-a-session)
- [Survive a restart](#survive-a-restart)
- [Receipts](#receipts)
- [Errors](#errors)
- [Buffers and stack](#buffers-and-stack)

## Add it to a build

The library is C99 with no heap allocation and no platform calls. Compile `src/*.c` with `include/` on the include path. One header pulls in everything:

```c
#include "transponder/transponder.h"
```

On ESP-IDF the repository root is a component. Depend on it from `main/idf_component.yml`:

```yaml
dependencies:
  kriss39/transponder:
    version: "*"
    override_path: "path/to/transponder"
```

Under **Component config → Transponder**, choose which signer port the component builds. [`examples/esp32-pay`](../examples/esp32-pay) is a complete firmware that uses it.

## The signer

Every payment is signed by a `trp_signer`: a P-256 key and a function that signs a 32-byte digest with it. Use one of the ports or write your own.

| Port | Key lives in | Init |
|---|---|---|
| [`ports/atecc608`](../ports/atecc608) | Microchip ATECC608A/B (built into the ESP32-WROOM-32SE) | `trp_atecc608_signer_init(&signer, &key, slot)` after `atcab_init()` |
| [`ports/apple`](../ports/apple) | The Secure Enclave of an Apple-silicon Mac | `trp_enclave_signer_init(&signer, &key)` |
| [`ports/mbedtls`](../ports/mbedtls) | Software (PSA Crypto). For testnet and boards without a secure element. | `trp_mbedtls_signer_import(&signer, &key, private_key)` |

```c
trp_signer signer;
trp_atecc608_key key;

if (trp_atecc608_signer_init(&signer, &key, 0) != TRP_OK) { /* no chip, or no key in slot 0 */ }
```

The device key's address is `trp_p256_address(signer.public_key, address)`. Print it once so the owner can authorize it.

## Authorize the device key

The device never holds the owner's key. The owner authorizes the device's P-256 key once on Tempo, as an **access key** with a spending limit, a token and an expiry. The chain enforces that limit: a lost or cloned device cannot spend past it, and the owner can revoke the key. Any wallet that can authorize P-256 access keys works. For Moderato testnet, [`tools/testnet/setup.mjs`](../tools/testnet/setup.mjs) does it with throwaway accounts.

For sessions, scope the key to the escrow precompile `0x4d50500000000000000000000000000000000000` with the selectors `open` (`0xedc53b00`) and `topUp` (`0xdc48471e`).

## Pay a charge

GET the resource. On a 402, pick the Tempo charge challenge from the `WWW-Authenticate` header, pay it, and send the request again.

```c
static char scratch[2 * 8192 + 16], credential[4608];
static uint8_t work[8192];
trp_challenge ch;
trp_charge_result result;

/* 1. The challenge. `www_authenticate` is every WWW-Authenticate value, comma-joined. */
if (trp_challenge_select(www_authenticate, len, "tempo", "charge", &ch, scratch, sizeof(scratch)) != TRP_OK)
    return; /* no Tempo charge offered */

/* 2. The device's own limits. The server only asks; this decides. */
static const uint64_t chains[] = {TRP_TEMPO_MODERATO};
trp_spend_policy policy = {0};
trp_u256_from_decimal("100000", 6, policy.max_amount); /* 0.10 of a 6-decimal token, per payment */
policy.chain_ids = chains;
policy.chain_id_count = 1;

/* 3. Who pays, and the transaction's limits. */
trp_charge_options opt = {0};
opt.owner = owner;                   /* the account the access key pays for */
opt.signer = &signer;
opt.policy = &policy;
opt.now = unix_time();               /* from SNTP; must be right to within a few seconds */
opt.valid_after = opt.now - 60 - random_below(86400); /* a random past second */
opt.gas_limit = 300000;
opt.max_fee_per_gas = 30000000000u;  /* required even when the server sponsors the fee */
opt.max_priority_fee_per_gas = 0;

/* 4. Sign. */
trp_err_t err = trp_tempo_charge(&ch, &opt, credential, sizeof(credential), work, sizeof(work), &result);
if (err == TRP_ERR_DENIED) return; /* outside the policy, or `approve` said no */

/* 5. Send the same request again with this header. */
http_set_header(trp_challenge_credential_header(&ch), credential); /* "Authorization: Payment ..." */
```

- **Proofs.** A challenge for an amount of zero asks the device to prove which account it pays for. `trp_tempo_charge` answers with a signed proof instead of a transaction (`result.proof` is 1), and nothing is paid.
- **Asking first.** Set `opt.approve` to get a last say before anything is signed, such as a button press on the device.
- **Splits.** Charges with up to `TRP_MAX_SPLITS` (4) extra recipients are paid in one transaction. The policy checks every recipient.

## Pay with a session

A session deposits once into an escrow channel. After that, each request is paid with a voucher: an off-chain signature over the running total. Only the open and the top-ups are transactions. The same device key signs everything.

```c
trp_session_request r;
trp_session s;
uint8_t deposit[32], salt[32], total[32];

trp_challenge_select(www_authenticate, len, "tempo", "session", &ch, scratch, sizeof(scratch));
trp_session_request_parse(&ch, &r);   /* r.price is the price per request */

/* Open: one deposit on chain, and the first request is paid. salt: 32 fresh random bytes. */
trp_session_open(&ch, &opt, deposit, salt, &s, credential, sizeof(credential), work, sizeof(work));
/* ...send it... */

/* Each later request: a voucher for the new running total (not the increment). */
trp_session_voucher(&s, &ch, &signer, total, credential, sizeof(credential), work, sizeof(work));

/* Out of deposit: top up, and count it only once the server accepts it. */
trp_session_top_up(&s, &ch, &opt, more, credential, sizeof(credential), work, sizeof(work));
/* 2xx: trp_session_top_up_confirmed(&s);   an error response: trp_session_top_up_failed(&s); */

/* Done: ask the server to settle and close the channel. */
trp_session_close(&s, &ch, &signer, credential, sizeof(credential), work, sizeof(work));
```

The rules the library enforces:

- Only `sessionProtocol` v2 on the TIP-1034 precompile. Any other escrow is refused, so a server cannot route the deposit elsewhere.
- The policy's `max_amount` limits the channel's whole deposit, top-ups included, and `approve` is asked for each.
- A voucher never goes down, never past the confirmed deposit, and raises the total by at least the server's `minVoucherDelta`.
- Every voucher is checked against the open channel: same chain, token and payee.

[`examples/host-pay/pay.c`](../examples/host-pay/pay.c) (`--session N`) is a complete loop with top-ups and retries.

## Survive a restart

A device that reboots mid-session loses the channel, and its deposit stays locked until the server closes it. To keep the channel instead:

1. **Save.** After every call that signs (open, voucher, top-up, close), call `trp_session_save` into 338 bytes of flash. Do it **before** sending the credential. That way the saved total is never below what the server holds. Save again after `top_up_confirmed` and `top_up_failed`.
2. **Load.** After the reboot, call `trp_session_load`. It refuses anything corrupted, or anything `trp_session_save` did not write.
3. **Sync.** Read the channel from the chain and apply the answer.

```c
uint8_t state[TRP_SESSION_STATE_LEN];
char rpc_body[256];

trp_session_save(&s, state);          /* before each credential goes out */
nvs_set_blob(nvs, "session", state, sizeof(state));

/* After a reboot: */
trp_session_load(&s, state, sizeof(state));
trp_session_state_request(&s, rpc_body, sizeof(rpc_body));  /* a JSON-RPC eth_call */
/* POST rpc_body to a Tempo RPC endpoint, then: */
err = trp_session_sync(&s, response, response_len, unix_time());
```

`trp_session_sync` sets the deposit to what the chain shows and settles a pending top-up either way. If the channel is gone or a close was requested, it marks the session closed: open a new one. While the last open or top-up could still land, it returns `TRP_ERR_PENDING` and changes nothing. That window lasts until a minute after the transaction's `tx_valid_before`; ask again after it.

Try it on a computer: `pay --session N --state FILE` saves to FILE and continues the channel on the next run.

## Receipts

A paid response carries a `Payment-Receipt` header. `trp_receipt_parse` reads it. `trp_receipt_verify(&receipt, "tempo", result.tx_hash)` checks that it reports success for the transaction the device signed. When the server sponsored the fee, it co-signed the transaction, which changes the hash. In that case pass `NULL` to check only the status.

## Errors

Every function that can fail returns a `trp_err_t`:

| Code | Meaning |
|---|---|
| `TRP_OK` | Done |
| `TRP_ERR_BUFFER` | An output or work buffer is too small |
| `TRP_ERR_INVALID` | Malformed input, or a call the session rules forbid |
| `TRP_ERR_UNSUPPORTED` | Valid, but not something this library does (another method, a v1 session, push-only) |
| `TRP_ERR_CRYPTO` | The signer failed |
| `TRP_ERR_NOT_FOUND` | No matching challenge |
| `TRP_ERR_DENIED` | The spending policy or `approve` refused |
| `TRP_ERR_PENDING` | A transaction may still land; ask again later |

## Buffers and stack

Nothing allocates. Make the buffers `static` to keep them off the task's stack.

| Buffer | Enough |
|---|---|
| `scratch` for parsing a header | 2 × header length + 16 |
| `work` / `out` for any call | 8 KB / 4.5 KB |
| A saved session | 338 bytes |

The deepest call, a charge with two splits, uses 2.9 KB of stack, plus the signer's own. On an ESP32, give the paying task 6 to 8 KB. Exact numbers per call are in [DESIGN.md](DESIGN.md#memory).

# Transponder design

Transponder is an MPP client in C for microcontrollers. A device holds a P-256 key that never leaves its hardware, the device's owner authorizes that key on Tempo as an access key with a spending limit, and the device pays MPP services with it.

This document records what the specs require and how the library maps onto them. Spec references are at the end.

## Goals

- **Pay MPP `charge` and `session` challenges from a microcontroller**, first on an ESP32 with the ESP32-WROOM-32SE module (ATECC608A built in) under ESP-IDF.
- **Keys stay in hardware.** The signing key lives in a secure element (Microchip ATECC608A first) and is non-exportable. Tempo verifies P-256 signatures natively, which is what makes this possible: an Ethereum-style chain would need secp256k1, which these chips don't offer.
- **The owner sets the limits, the chain enforces them.** The device key is a Tempo access key with a spending limit, a token and an expiry. A stolen device can spend at most what is left on its key, and the owner can revoke it.
- **No heap.** Every function writes into caller-owned buffers. Nothing allocates.
- **Portable core.** Encoding, hashing and protocol logic are plain C99 with no platform calls. Signing, randomness, time and HTTP sit behind small interfaces with per-platform backends.
- **Conformance.** Pass the cross-SDK vectors in [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) that the official SDKs run in CI.

Not goals for now: server-side verification, `session` v1 (contract-backed channels), and payment methods other than Tempo.

## The payment, step by step

```
 Device                                   MPP service                    Tempo
 ──────                                   ───────────                    ─────
 GET /reading ───────────────────────────▶
                ◀─────────── 402 + WWW-Authenticate: Payment method="tempo" intent="charge"
 parse challenge, decode `request`
 build Tempo tx: transfer(recipient, amount) on `currency`
 sender hash = keccak256(0x76 || rlp(fields))
 secure element signs keccak256(0x04 || sender hash || owner address)
 GET /reading
   Authorization: Payment <base64url credential, payload.type="transaction">
                                          add fee payer signature (0x78) ─▶
                                          broadcast ───────────────────────▶
                ◀────────── 200 + Payment-Receipt
```

The device uses **pull mode**: it signs and the server broadcasts. That keeps the device off the RPC path for submission, and when the server sets `methodDetails.feePayer: true` it also pays the network fee.

## What has to be built

| Layer | Module | Status |
|---|---|---|
| Encoding | hex | done |
| Hashing | Keccak-256 | done |
| Encoding | RLP writer | done |
| Encoding | base64url | done |
| MPP core | `WWW-Authenticate: Payment` parser (several challenges per response) | done, passes the mpp-tools vectors |
| MPP core | JSON reader and writer (depth cap, UTF-8 checks, duplicate keys rejected) | done |
| MPP core | credential builder: `{challenge, payload, source}` → JSON → base64url | done, passes the mpp-tools vectors |
| Tempo | ABI calldata for `transferWithMemo`, MPP attribution memo | done |
| Tempo | 0x76 transaction: fields, sender hash, signed envelope | done, byte-identical to ox |
| Tempo | P-256 signature (130 bytes, low-s) and Keychain wrapper (`0x04`) | done |
| Tempo | address from P-256 public key | done |
| Tempo | charge flow: challenge → transaction → signature → credential (`trp_tempo_charge`) | done, credential identical to the reference |
| Tempo | proof credential for zero-amount charges (EIP-712 `Proof`, Keychain V2 signature) | done, identical to ox, accepted by mppx on Moderato |
| Tempo | spending policy checked before signing: amount cap, token, recipient and chain allow-lists, approval callback | done |
| Tempo | session v2 (TIP-1034 channel escrow precompile): open, voucher, top-up, close | done, credentials identical to ox; run end to end on Moderato, with a Secure Enclave key too |
| Signers | software P-256 (mbedTLS PSA API, `ports/mbedtls`) for host tests and boards without a secure element | done, signatures identical to ox |
| Signers | Apple Secure Enclave through CryptoKit (`ports/apple`, pre-hashed P-256) | done, paid on Moderato |
| Signers | ATECC608A through cryptoauthlib (`ports/atecc608`) | done, builds on ESP-IDF; not yet run on a chip |
| Platform | host demo with libcurl (`examples/host-pay`) | done, paid on Moderato |
| Platform | ESP-IDF example: Wi-Fi, SNTP, esp_http_client, the 402 flow (`examples/esp32-pay`) | builds in CI on ESP-IDF v5.5 and v6.0; not yet on hardware |
| MPP core | `Payment-Receipt` parser | done |
| Conformance | mpp-tools adapter (JSON ABI described in `HARNESS_SPEC.md`) | done, 121/121 on the official runner |
| Robustness | libFuzzer targets for the parsers and the whole payment path (`fuzz/`), in CI | done |

## Tempo transaction (type 0x76)

From the Tempo Transactions specification. Fields, in RLP order:

```
0x76 || rlp([
  chain_id, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
  calls,                  // [[to, value, input], ...], at least one
  access_list,            // [] for us
  nonce_key, nonce,       // 2D nonces: nonce_key > 0 is an independent lane
  valid_before,           // 0x80 if none; must not exceed the challenge's `expires`
  valid_after,            // 0x80 if none
  fee_token,              // 0x80 if none
  fee_payer_signature,    // 0x80 if none, [v, r, s] once the server signs
  aa_authorization_list,  // [] for us
  key_authorization?,     // omitted entirely when absent
  sender_signature        // only in the signed envelope
])
```

**Sender hash.** The device signs `keccak256(0x76 || rlp([...]))` over the fields above without `sender_signature`, with two rules:

- When the server will pay fees (`feePayer: true`): `fee_token` is encoded as `0x80` and `fee_payer_signature` as the single byte `0x00` (a placeholder). The server later picks the fee token and signs under the `0x78` domain.
- Otherwise: `fee_token` holds a USD TIP-20 token address and `fee_payer_signature` is `0x80`.

**Calls.** One call per payment: `to` = the TIP-20 token (`currency`), `value` = 0, `input` = `transfer(recipient, amount)`, or `transferWithMemo(recipient, amount, memo)` when `methodDetails.memo` is present. Split payments add one call per split.

### Signatures

- **P-256**, 130 bytes: `0x01 || r || s || pub_x || pub_y || pre_hash`. When `pre_hash` is 1 the verifier hashes the digest with SHA-256 first. A secure element signs a 32-byte digest directly, so the device sends `pre_hash = 0`.
- **Keychain**, for access keys: `0x04 || owner_address (20) || inner signature`. The inner P-256 signature is over `keccak256(0x04 || sender_hash || owner_address)`, not over the sender hash itself.
- **Address of a P-256 key**: the last 20 bytes of `keccak256(pub_x || pub_y)`. This is the access key's `key_id` that the owner authorizes.

### Who authorizes the device key

The owner's root key (a passkey, in practice) signs a `KeyAuthorization` with `key_type = 1` (P-256), `key_id` = the device address, an `expiry`, and `limits` (token, amount, period). This happens once, from a browser, not on the device. Pitstop's Guard page already authorizes P-256 access keys this way, so it could provision devices too.

## Memory

Nothing allocates. The caller passes every buffer, and can make them `static` to keep them off the task's stack:

| Buffer | Size that is enough |
|---|---|
| `scratch` for `trp_challenge_parse` / `trp_challenge_select` / `trp_receipt_parse` | 2 × header length + 16 |
| `work` for a charge | 3 KB, plus about 1.1 KB per split (7.5 KB with four) |
| `out` for a charge | 1.7 KB, plus about 0.6 KB per split (4.1 KB with four) |
| `work` / `out` for session open and top-up | 6.4 KB / 3.5 KB |
| `work` / `out` for a voucher or close | 4.5 KB / 2.6 KB |
| A saved session (`trp_session_save`) | 338 bytes |
| The channel read (`trp_session_state_request`) / its answer | 201 bytes / about 250 bytes |

Measured with a 43-character challenge id and a short realm; longer challenge fields add about 4/3 of their length to `out`. 8 KB of `work` and 4.5 KB of `out` cover every call.

Stack, measured by `make stack` (`tools/stack`) on an arm64 Mac at `-O2` and `-Os`, with a stub signer:

| Entry point | Stack |
|---|---|
| `trp_challenge_parse` | 1.5 KB |
| `trp_tempo_charge` (two splits, parse included) | 2.9 KB |
| `trp_session_open` (parse included) | 2.5 KB |
| `trp_session_voucher` / `top_up` / `close` | 1.8 / 2.2 / 1.9 KB |
| `trp_session_load` + `trp_session_sync` | 1.5 KB |

The signer's own stack comes on top: little for a secure element, more for software P-256. Frames differ by CPU and compiler (Xtensa's register windows add some), so on an ESP32 give the paying task 6 to 8 KB until it is measured there.

## Conformance

`tests/conformance_vectors.h` is generated from the cross-SDK vectors in tempoxyz/mpp-tools by `tools/gen_conformance.py`. Transponder follows the TypeScript reference SDK (mppx), so scenarios limited to other adapters are skipped. One deliberate difference from the Python SDK: an unterminated quoted-string is an error (as in mppx), not ignored.

Credential JSON keys are written in mppx's order: `id, realm, method, intent, description, digest, expires, header, opaque, request`, then `payload`, then `source`.

## Resolved

- **Nonces.** The reference SDK uses expiring nonces for charges: `nonce_key = 2^256 - 1`, `nonce = 0`, `valid_before` at most 25 seconds ahead (and not past the challenge's `expires`), and `valid_after` a random past timestamp so otherwise identical transactions differ. The device needs the time (SNTP), not a nonce from the chain.
- **Memo.** Every SDK payment uses `transferWithMemo`. If the request has `methodDetails.memo`, that memo is used, as the spec requires; otherwise the MPP attribution memo (see `trp_mpp_attribution_memo`). mppx's client always writes the attribution memo, which conflicts with a server-set memo; Transponder follows the spec, and an mppx server accepts either case.
- **Signature details.** Tempo and ox require low-s P-256 signatures; the encoder normalizes `s`. Keychain V2 signs `keccak256(0x04 || sender_hash || owner)`.

- **Sessions.** Only `sessionProtocol: "v2"` is supported: channels live in the TIP-20 channel escrow precompile (`0x4d50500000000000000000000000000000000000`, TIP-1034), and any other `escrowContract` is refused, so a deposit can only go to the precompile. v2 vouchers accept TIP-1020 primitive signatures, P-256 included, so the device key is both the Keychain signer of the `open` and `topUp` transactions and the channel's `authorizedSigner`: vouchers come from the secure element too, and no secp256k1 key is needed. The EIP-712 domain is `TIP20 Channel Reserve`, version `1`; amounts are uint96. The channel id hashes the descriptor with the transaction's expiring-nonce hash (`keccak256(signing payload || owner)`), so `open` must be signed before the id is known. The client refuses a voucher that goes down or past the deposit, a raise below the server's `minVoucherDelta`, a voucher signed by any key but the channel's `authorizedSigner` or after a close, and a challenge whose chain, escrow, token or payee differs from the open channel's. A top-up stays pending until the caller reports the server's answer (`trp_session_top_up_confirmed` or `_failed`), so a failed request cannot make the device believe in a deposit that is not on chain, and only one top-up is pending at a time. For sessions the policy's `max_amount` limits the channel's whole deposit, and `approve` is asked for the open deposit and each top-up. The `open` carries a voucher for one unit, the price, as mppx's client does: the request that opens the channel is also paid by it. On Moderato the deposit counts against the access key's spending limit, so the chain caps what a session key can lock in channels.

- **Restarts.** A device that loses its session mid-channel cannot pay with it again, and its deposit stays locked until the server closes the channel. So the session can be saved (`trp_session_save`, 338 bytes with a version and a checksum) and loaded back; `trp_session_load` refuses anything with a bad checksum or a channel ID that does not match its descriptor. The rule is to save after every call that signs and before its credential is sent: then the saved cumulative is never below what the server holds, and the device never needs the server's word for it. mppx can also hint at a channel in the challenge (`methodDetails.sessionSnapshot`), but only when the request already names the channel, which a device that lost its state cannot do, and trusting the hint's amounts would take a P-256 verify on the device; so Transponder does not use it. After loading, the device reads the channel from the escrow (`getChannelState`, an `eth_call` that `trp_session_state_request` writes as a JSON-RPC body) and `trp_session_sync` applies the answer: the chain's deposit replaces the saved one, a pending top-up is confirmed if the deposit includes it, a channel with no deposit or a close request is marked closed, and the cumulative rises to what the server has settled if that is more. Until a minute after the last open or top-up transaction's `valid_before` (at most 25 seconds after signing) that transaction could still land, so sync answers `TRP_ERR_PENDING` and changes nothing rather than give up on a deposit that may yet appear. Verified on Moderato with a Secure Enclave key on 2026-10-14: a channel opened in one run was restored in the next, topped up and paid three more vouchers, and closed from a third.

## Open questions

- **Gas values.** `gas_limit` and the fee fields need either an RPC estimate or safe constants for a TIP-20 transfer. With a fee payer, check whether the server tolerates fixed values.

## References

- MPP core: [Payment HTTP Authentication Scheme](https://paymentauth.org) (IETF draft)
- Tempo charge: `specs/methods/tempo/draft-tempo-charge-00.md` in [tempoxyz/mpp-specs](https://github.com/tempoxyz/mpp-specs)
- [Tempo Transactions specification](https://tempo.xyz/developers/docs/protocol/transactions/spec-tempo-transaction)
- [Account Keychain precompile](https://tempo.xyz/developers/docs/protocol/transactions/AccountKeychain)
- Conformance: [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools)

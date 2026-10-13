# Transponder design

Transponder is an MPP client in C for microcontrollers. A device holds a P-256 key that never leaves its hardware, the device's owner authorizes that key on Tempo as an access key with a spending limit, and the device pays MPP services with it.

This document records what the specs require and how the library maps onto them. Spec references are at the end.

## Goals

- **Pay MPP `charge` challenges from a microcontroller**, first on an ESP32 with the ESP32-WROOM-32SE module (ATECC608A built in) under ESP-IDF.
- **Keys stay in hardware.** The signing key lives in a secure element (Microchip ATECC608A first) and is non-exportable. Tempo verifies P-256 signatures natively, which is what makes this possible: an Ethereum-style chain would need secp256k1, which these chips don't offer.
- **The owner sets the limits, the chain enforces them.** The device key is a Tempo access key with a spending limit, a token and an expiry. A stolen device can spend at most what is left on its key, and the owner can revoke it.
- **No heap.** Every function writes into caller-owned buffers. Nothing allocates.
- **Portable core.** Encoding, hashing and protocol logic are plain C99 with no platform calls. Signing, randomness, time and HTTP sit behind small interfaces with per-platform backends.
- **Conformance.** Pass the cross-SDK vectors in [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) that the official SDKs run in CI.

Not goals for now: server-side verification, the `session` intent (its vouchers are secp256k1 EIP-712 signatures, see below), and payment methods other than Tempo.

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
| Signers | software P-256 (mbedTLS PSA API, `ports/mbedtls`) for host tests and boards without a secure element | done, signatures identical to ox |
| Signers | Apple Secure Enclave through CryptoKit (`ports/apple`, pre-hashed P-256) | done, paid on Moderato |
| Signers | ATECC608A through cryptoauthlib | |
| Platform | host demo with libcurl (`examples/host-pay`) | done, paid on Moderato |
| Platform | ESP-IDF: HTTP client, time, JSON-RPC calls | |
| MPP core | `Payment-Receipt` parser | done |
| Conformance | mpp-tools adapter (JSON ABI described in `HARNESS_SPEC.md`) | done, 121/121 on the official runner |

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

## Conformance

`tests/conformance_vectors.h` is generated from the cross-SDK vectors in tempoxyz/mpp-tools by `tools/gen_conformance.py`. Transponder follows the TypeScript reference SDK (mppx), so scenarios limited to other adapters are skipped. One deliberate difference from the Python SDK: an unterminated quoted-string is an error (as in mppx), not ignored.

Credential JSON keys are written in mppx's order: `id, realm, method, intent, description, digest, expires, header, opaque, request`, then `payload`, then `source`.

## Resolved

- **Nonces.** The reference SDK uses expiring nonces for charges: `nonce_key = 2^256 - 1`, `nonce = 0`, `valid_before` at most 25 seconds ahead (and not past the challenge's `expires`), and `valid_after` a random past timestamp so otherwise identical transactions differ. The device needs the time (SNTP), not a nonce from the chain.
- **Memo.** Every SDK payment uses `transferWithMemo`. If the request has `methodDetails.memo`, that memo is used, as the spec requires; otherwise the MPP attribution memo (see `trp_mpp_attribution_memo`). mppx's client always writes the attribution memo, which conflicts with a server-set memo; Transponder follows the spec, and an mppx server accepts either case.
- **Signature details.** Tempo and ox require low-s P-256 signatures; the encoder normalizes `s`. Keychain V2 signs `keccak256(0x04 || sender_hash || owner)`.

## Open questions

- **Gas values.** `gas_limit` and the fee fields need either an RPC estimate or safe constants for a TIP-20 transfer. With a fee payer, check whether the server tolerates fixed values.
- **Sessions.** Session vouchers are EIP-712 secp256k1 signatures. A clean design: the secure element's P-256 key opens the channel and names a short-lived secp256k1 `authorizedSigner` held in RAM. Later.

## References

- MPP core: [Payment HTTP Authentication Scheme](https://paymentauth.org) (IETF draft)
- Tempo charge: `specs/methods/tempo/draft-tempo-charge-00.md` in [tempoxyz/mpp-specs](https://github.com/tempoxyz/mpp-specs)
- [Tempo Transactions specification](https://tempo.xyz/developers/docs/protocol/transactions/spec-tempo-transaction)
- [Account Keychain precompile](https://tempo.xyz/developers/docs/protocol/transactions/AccountKeychain)
- Conformance: [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools)

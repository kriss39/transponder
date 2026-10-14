# Transponder

**An [MPP](https://mpp.dev) client in C for microcontrollers. The key stays in the chip; the owner sets the limit.**

Transponder lets a device pay for an API over the Machine Payments Protocol, the HTTP 402 standard from Tempo and Stripe. It answers a `402 Payment Required` challenge with a signed Tempo transaction, and the signing key never leaves the device's secure element.

> **Mainnet, 2026-10-14:** a key in the Secure Enclave of an M2 Mac paid Tempo's own storage service (`storage.mpp.tempo.xyz`) 0.0001 USDC.e on Tempo mainnet, in [`0x1aef8d08…dfef0e`](https://explore.tempo.xyz/tx/0x1aef8d08df328452adbc582a5b39d4869f066c4319176051d382e223ebdfef0e). The owner's wallet had authorized the key as an access key with a 0.3 USDC.e daily limit; the server sponsored the fee. The private key never left the chip.
>
> **Status: early.** Transponder paid its first MPP service on Tempo testnet (Moderato) on 2026-10-14: a local mppx server charged 0.01 AlphaUSD, the payment settled in [`0x3c01ac56…83ab10`](https://explore.testnet.tempo.xyz/tx/0x3c01ac563dc3cd18a7052de8635103777e41487a033072c68232a8557583ab10), signed by an access key with a 5 AlphaUSD limit. The same day it paid again with a key held in the Secure Enclave of an M2 Mac ([`0xb0b71ac4…8f79f6`](https://explore.testnet.tempo.xyz/tx/0xb0b71ac46e7901b3917fa68eaaad457242faee905199d3807cbbdb9a718f79f6)): the private key never left the chip, which is the model for the ESP32 + ATECC608A version that comes next. It also runs MPP sessions: with a Secure Enclave key it opened a channel in the TIP-1034 escrow precompile ([`0xc3e29bf3…307760`](https://explore.testnet.tempo.xyz/tx/0xc3e29bf380e6f657aa7f32f42140908733caeb5b8e3e828301227ada1e307760)), paid for five requests with vouchers signed in the enclave, topped the channel up once, and the server closed it at the last voucher ([`0x9634fecf…a85c36`](https://explore.testnet.tempo.xyz/tx/0x9634fecf09650a27da42b37fe8d8d96ab5be7a60c94aedba212908927ba85c36)).

## Why

- **Hardware-held keys.** Tempo verifies P-256 signatures natively, the curve that secure elements like the ATECC608A sign with. The device's key is generated inside the chip and can't be read out.
- **Limits enforced by the chain.** The device key is a Tempo access key: the owner authorizes it once with a spending limit, a token and an expiry. A lost or cloned device can't spend past that, and the owner can revoke it.
- **Small and predictable.** C99, no heap allocation, caller-owned buffers, no platform calls in the core.

## Roadmap

- [x] Hex, Keccak-256, RLP writer, with host tests
- [x] MPP core: challenge parsing, `request` decoding, credential encoding, checked against the [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) conformance vectors
- [x] Tempo `charge`: 0x76 transaction, P-256 and Keychain signatures, the full challenge → credential flow, checked byte for byte against ox (the library mppx uses)
- [x] Proofs: a zero-amount challenge is answered with a signed EIP-712 proof of the account the device pays for, and nothing is paid; accepted by a stock mppx server
- [x] Spending policy checked on the device before it signs: amount cap, token, recipient and chain allow-lists
- [x] Tempo `session` (v2, the TIP-1034 channel escrow precompile): open, vouchers, top-up and close, all signed by the same P-256 key, credentials byte-identical to ox, run end to end against a stock mppx server on Moderato
- [x] Software P-256 signer on the PSA Crypto API (mbedTLS 3.x and 4.x)
- [x] Apple Secure Enclave signer (`ports/apple`): a hardware-held key on any Apple-silicon Mac
- [x] ATECC608A signer (`ports/atecc608`), compiled in CI; not yet run on a chip
- [x] A first payment on Tempo testnet from a computer, through a stock mppx server
- [x] ESP-IDF example ([`examples/esp32-pay`](examples/esp32-pay)): Wi-Fi, SNTP, the 402 flow and either signer; builds in CI on ESP-IDF v5.5 and v6.0
- [ ] On hardware: an ESP32-WROOM-32SE (ATECC608A built in) pays a live MPP endpoint on Tempo testnet
- [x] Passes the official [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) conformance runner: 121/121 vector checks, through the adapter in [`tools/conformance`](tools/conformance)

The design, including the transaction layout and signing rules, is in [docs/DESIGN.md](docs/DESIGN.md).

## Build and test on a computer

You need a C compiler and `make`.

```sh
make test   # build and run the unit tests
make asan   # the same, with address and undefined-behaviour sanitizers
make test-mbedtls   # the software signer (needs mbedTLS: brew install mbedtls)
make fuzz-run       # libFuzzer on the header parsers and on the whole payment path (clang; on macOS: brew install llvm)
```

The fuzz targets in [`fuzz/`](fuzz) play a hostile server: one feeds arbitrary `WWW-Authenticate`, `Payment-Receipt` and JSON to the parsers, the other feeds an arbitrary `request` through charge, proof, open, voucher, top-up and close. CI fuzzes each for a minute on every push.

To refresh the conformance vectors from a checkout of tempoxyz/mpp-tools:

```sh
python3 tools/gen_conformance.py path/to/mpp-tools
```

## Try a testnet payment

You need Node.js, mbedTLS and libcurl (macOS ships libcurl). Everything uses throwaway testnet accounts.

```sh
cd tools/testnet && npm install
node setup.mjs     # owner account from the faucet, device key authorized with a 5 AlphaUSD limit
node server.mjs &  # a local MPP service: 0.01 AlphaUSD per reading
cd ../.. && make pay
set -a; . .testnet/device.env; set +a
./build/pay http://127.0.0.1:8402/reading
```

Pay per request through a session instead: one deposit on chain, then a signed voucher per request. The session key setup.mjs authorizes may only open and top up channels in the escrow precompile, with a 1 AlphaUSD budget:

```sh
./build/pay --session 5 http://127.0.0.1:8402/stream   # 0.001 AlphaUSD per reading
```

On an Apple-silicon Mac, sign with a key in the Secure Enclave instead:

```sh
make enclave-key pay-enclave
./build/enclave-key create .testnet/enclave.key           # for charges
./build/enclave-key create .testnet/enclave-session.key   # for sessions
cd tools/testnet && node setup.mjs && cd ../..   # authorizes the enclave keys too
set -a; . .testnet/device.env; set +a
./build/pay http://127.0.0.1:8402/reading
```

## Use with ESP-IDF

The repository root is an ESP-IDF component (`CMakeLists.txt` and `idf_component.yml`). Depend on it from your project's `main/idf_component.yml` (`transponder: {path: <checkout>}`) or put it under `components/`. Build the signer port you use (`ports/atecc608` or `ports/mbedtls`) in your own component, as the example does. [`examples/esp32-pay`](examples/esp32-pay) is a complete firmware: CI builds it on every push, but it has not run on a board yet.

## License

MIT

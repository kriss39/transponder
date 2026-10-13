# Transponder

**An [MPP](https://mpp.dev) client in C for microcontrollers. The key stays in the chip; the owner sets the limit.**

Transponder lets a device pay for an API over the Machine Payments Protocol, the HTTP 402 standard from Tempo and Stripe. It answers a `402 Payment Required` challenge with a signed Tempo transaction, and the signing key never leaves the device's secure element.

> **Status: early.** The MPP protocol core (challenges and credentials) and the encoding and hashing layer are in place and tested. Signing Tempo payments is next, so payments do not work yet.

## Why

- **Hardware-held keys.** Tempo verifies P-256 signatures natively, the curve that secure elements like the ATECC608A sign with. The device's key is generated inside the chip and can't be read out.
- **Limits enforced by the chain.** The device key is a Tempo access key: the owner authorizes it once with a spending limit, a token and an expiry. A lost or cloned device can't spend past that, and the owner can revoke it.
- **Small and predictable.** C99, no heap allocation, caller-owned buffers, no platform calls in the core.

## Roadmap

- [x] Hex, Keccak-256, RLP writer, with host tests
- [x] MPP core: challenge parsing, `request` decoding, credential encoding, checked against the [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) conformance vectors
- [ ] Tempo `charge`: 0x76 transaction, P-256 and Keychain signatures
- [ ] Signers: software P-256 (mbedTLS) and ATECC608A
- [ ] ESP-IDF example: an ESP32-WROOM-32SE (ATECC608A built in) pays a live MPP endpoint on Tempo testnet
- [ ] A harness adapter so the mpp-tools conformance runner can test Transponder directly, in CI

The design, including the transaction layout and signing rules, is in [docs/DESIGN.md](docs/DESIGN.md).

## Build and test on a computer

You need a C compiler and `make`.

```sh
make test   # build and run the unit tests
make asan   # the same, with address and undefined-behaviour sanitizers
```

To refresh the conformance vectors from a checkout of tempoxyz/mpp-tools:

```sh
python3 tools/gen_conformance.py path/to/mpp-tools
```

## Use with ESP-IDF

The repository root is an ESP-IDF component (`CMakeLists.txt` and `idf_component.yml`). Add it under your project's `components/` directory. This path is not tested yet.

## License

MIT

# ESP32 pays an MPP endpoint

An ESP32 joins Wi-Fi, sets its clock over SNTP, and requests a URL every minute. When the server answers `402 Payment Required` with a Tempo charge challenge, the device checks the challenge against its own spending policy, signs the payment with its device key, and retries with the credential.

The device key lives in one of two places:

- **ATECC608A secure element** (default). On an ESP32-WROOM-32SE module the chip is built in. The key is generated inside it and never leaves it.
- **Software key** in the firmware, signed with mbedTLS. Use this only for boards without a secure element, and only on testnet.

> **Status:** this example compiles in CI against ESP-IDF v5.5 and v6.0 with both signers. It has not run on hardware yet.

## Configure

```sh
cd examples/esp32-pay
idf.py set-target esp32
idf.py menuconfig
```

Under **Transponder example**, set:

- the Wi-Fi network and password
- the URL
- the owner account
- the signer

Under **Component config → esp-cryptoauthlib**, set the ATECC608A chip type (Trust&Go, TrustFLEX or TrustCustom), plus its I2C pins and address. The defaults are SDA 21, SCL 22. Check them against your module's datasheet.

## Authorize the device key

On boot the device logs its key address:

```
I (512) transponder: device key address 0x…
```

The owner authorizes that address once, as a Tempo access key with a spending limit. For Moderato testnet, `tools/testnet/setup.mjs` does this for the keys it knows about. Adapt it, or use any wallet that can authorize P-256 access keys. The chain enforces the limit; the device can never spend past it.

To pay the local test server from the board, start it on your network:

```sh
cd tools/testnet && HOST=0.0.0.0 node server.mjs
```

Then set the URL to `http://<your computer's address>:8402/reading`.

## Build and flash

```sh
idf.py build flash monitor
```

To build with the software signer instead:

```sh
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.software" build
```

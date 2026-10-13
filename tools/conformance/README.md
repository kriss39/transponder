# Conformance adapter

`adapter.c` lets the [tempoxyz/mpp-tools](https://github.com/tempoxyz/mpp-tools) conformance runner test Transponder through the JSON ABI in `conformance/HARNESS_SPEC.md`: one JSON request on stdin, one JSON response on stdout.

It answers every vector operation the runner checks: `challenge.parse`, `challenge.format`, `challenge.id`, `credential.parse`, `credential.format`, `receipt.parse`, `receipt.format`, `base64url.encode`, `base64url.decode`. The client-side ones call the library. The server-side formatting ones (`challenge.format`, `challenge.id`, `credential.parse`, `receipt.format`) live only in the adapter, since a device never issues challenges; `challenge.id` carries its own SHA-256/HMAC (`--self-test` checks it against RFC 4231).

Run it against a checkout of mpp-tools:

```sh
make conformance-adapter
mkdir -p path/to/mpp-tools/conformance/adapters/transponder
# copy adapter.json there and set "command" to the absolute path of build/trp-conformance-adapter
cd path/to/mpp-tools/conformance
uv run --python 3.12 python scripts/vector_runner.py --adapter transponder
```

Result on 2026-10-14 with mpp-tools@7ff2338: 121 checks, 121 passed.

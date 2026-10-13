# Transponder Telemetry on Cloudflare Workers

A public MPP service on Tempo testnet that Transponder devices (or any MPP client) can pay: `GET /reading` costs 0.01 AlphaUSD on Moderato. Built with mppx, the reference SDK.

```sh
npm install
printf 'MPP_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > .dev.vars
npm run dev                       # http://127.0.0.1:8787, no Cloudflare account needed

```

To deploy to a Cloudflare account other than the one `wrangler login` remembers, give this folder its own API token (template "Edit Cloudflare Workers") in `.env.deploy`, which is git-ignored:

```sh
# .env.deploy
CLOUDFLARE_API_TOKEN=...
CLOUDFLARE_ACCOUNT_ID=...
```

```sh
set -a; . ./.env.deploy; set +a
printf 'MPP_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > /tmp/secrets.env
npx wrangler deploy --secrets-file /tmp/secrets.env && rm /tmp/secrets.env
```

Notes:
- `wrangler.toml` aliases `@modelcontextprotocol/sdk/types.js` to a stub: mppx imports it only for MCP tool calls, which this Worker does not serve.
- Testnet only. `MERCHANT` is a throwaway Moderato address.
- Tested locally on 2026-10-14: `./build/pay http://127.0.0.1:8787/reading` paid it with a Secure Enclave key.

// A public MPP service on Tempo testnet for Transponder devices to pay.
//
//   GET /          what this is and how to pay it
//   GET /reading   one "sensor reading", 0.01 AlphaUSD on Moderato, paid over MPP
//
// Built with mppx, the reference MPP SDK. Testnet only: payments use faucet
// tokens and go to a throwaway address.

import { Mppx, tempo } from 'mppx/server'

let mppx

function payments(env) {
  mppx ??= Mppx.create({
    methods: [tempo.charge({ currencies: [env.TOKEN], recipient: env.MERCHANT, testnet: true })],
    secretKey: env.MPP_SECRET_KEY,
  })
  return mppx
}

// A plausible indoor temperature that drifts through the day.
function reading() {
  const t = Date.now() / 3_600_000
  return Math.round((21 + 1.5 * Math.sin(t / 3) + 0.3 * Math.sin(t * 7)) * 10) / 10
}

const escape = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])

function page(origin, env) {
  const url = `${origin}/reading`
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Transponder demo</title>
<style>
  :root { color-scheme: light dark; --fg: #1b1b1f; --bg: #fafaf7; --muted: #5d5d66; --line: #e2e2dc; --code: #f0f0ea; }
  @media (prefers-color-scheme: dark) { :root { --fg: #ececf0; --bg: #141416; --muted: #a0a0aa; --line: #2c2c31; --code: #1e1e22; } }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.55 system-ui, sans-serif; }
  main { max-width: 680px; margin: 0 auto; padding: 40px 16px 64px; }
  h1 { font-size: 28px; margin: 0 0 4px; }
  p.lead { color: var(--muted); margin-top: 0; }
  pre { background: var(--code); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; overflow-x: auto; font-size: 13px; }
  code { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; }
  dt { color: var(--muted); } dd { margin: 0; word-break: break-all; }
  a { color: inherit; }
  footer { margin-top: 40px; color: var(--muted); font-size: 14px; }
</style>
</head>
<body>
<main>
  <h1>Transponder demo</h1>
  <p class="lead">A paid API on Tempo testnet for machines. Each reading costs ${escape(env.PRICE)} AlphaUSD, paid over the Machine Payments Protocol (HTTP 402).</p>

  <dl>
    <dt>Endpoint</dt><dd><code>GET ${escape(url)}</code></dd>
    <dt>Price</dt><dd>${escape(env.PRICE)} AlphaUSD per request</dd>
    <dt>Network</dt><dd>Tempo testnet (Moderato, chain 42431)</dd>
    <dt>Pays to</dt><dd><a href="https://explore.testnet.tempo.xyz/address/${escape(env.MERCHANT)}">${escape(env.MERCHANT)}</a></dd>
  </dl>

  <h2>See the challenge</h2>
  <pre><code>curl -i ${escape(url)}</code></pre>

  <h2>Pay with Transponder</h2>
  <p><a href="https://github.com/kriss39/transponder">Transponder</a> is an MPP client in C for microcontrollers. Its key stays in a secure element and the account owner caps what it can spend. From a computer:</p>
  <pre><code>make pay
set -a; . .testnet/device.env; set +a
./build/pay ${escape(url)}</code></pre>

  <h2>Or with the reference SDK</h2>
  <pre><code>npx mppx ${escape(url)}</code></pre>

  <footer>Independent demo, not affiliated with Tempo or Stripe. Testnet only: no real money moves here.</footer>
</main>
</body>
</html>`
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (url.pathname === '/') {
      return new Response(page(url.origin, env), {
        headers: { 'content-type': 'text/html; charset=utf-8' },
      })
    }

    if (url.pathname === '/reading') {
      const result = await payments(env).charge({ amount: env.PRICE, description: 'One sensor reading' })(request)
      if (result.status === 402) return result.challenge
      return result.withReceipt(
        Response.json({ reading: reading(), unit: 'C', at: new Date().toISOString(), network: 'tempo-moderato' }),
      )
    }

    return new Response('not found\n', { status: 404 })
  },
}

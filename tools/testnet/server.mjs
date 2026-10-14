// A local MPP service on Moderato testnet, built with the reference SDK.
//
//   node server.mjs            # http://127.0.0.1:8402
//   HOST=0.0.0.0 node server.mjs   # reachable from a board on the same network
//
//   GET /reading   charge: 0.01 AlphaUSD per reading
//   GET /stream    session: 0.001 AlphaUSD per reading, paid with vouchers
//                  from a channel in the TIP-1034 escrow precompile
//
// Run setup.mjs first: it writes the merchant address this server charges to.
// The session route closes channels on chain as the merchant, so it reads the
// merchant's throwaway testnet key from .testnet/state.json.

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import http from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Mppx, Store, tempo } from 'mppx/server'
import { privateKeyToAccount } from 'viem/accounts'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const config = JSON.parse(readFileSync(join(root, '.testnet', 'server.json'), 'utf8'))
const host = process.env.HOST ?? '127.0.0.1'
const port = Number(process.env.PORT ?? 8402)
const state = JSON.parse(readFileSync(join(root, '.testnet', 'state.json'), 'utf8'))
const merchant = privateKeyToAccount(state.merchantPrivateKey)
if (merchant.address !== config.merchant) throw new Error('server.json and state.json disagree; run setup.mjs')

const mppx = Mppx.create({
  methods: [
    tempo.charge({ currencies: [config.token], recipient: config.merchant, testnet: true }),
    tempo.session({
      account: merchant,
      currencies: [config.token],
      feeToken: config.token,
      store: Store.memory(),
      suggestedDeposit: '0.003',
      testnet: true,
      unitType: 'reading',
    }),
  ],
  secretKey: randomBytes(32).toString('hex'),
})
const charge = mppx.charge({ amount: '0.01', description: 'One sensor reading' })
const session = mppx.session({ amount: '0.001', description: 'Sensor readings, paid per reading' })

async function handle(request) {
  const url = new URL(request.url)
  const route = { '/reading': charge, '/stream': session }[url.pathname]
  if (!route) return new Response('not found\n', { status: 404 })
  const result = await route(request)
  if (result.status === 402) return result.challenge
  return result.withReceipt(Response.json({ reading: 21.5, unit: 'C', paid: true }))
}

http
  .createServer(async (req, res) => {
    try {
      const request = new Request(`http://${req.headers.host}${req.url}`, {
        method: req.method,
        headers: Object.entries(req.headers).flatMap(([k, v]) =>
          Array.isArray(v) ? v.map((x) => [k, x]) : [[k, v]],
        ),
      })
      const response = await handle(request)
      const headers = {}
      response.headers.forEach((value, key) => {
        headers[key] = value
      })
      res.writeHead(response.status, headers)
      res.end(Buffer.from(await response.arrayBuffer()))
      console.log(req.method, req.url, '->', response.status)
    } catch (err) {
      console.error(err)
      res.writeHead(500)
      res.end('error\n')
    }
  })
  .listen(port, host, () => {
    console.log(`MPP test service on http://${host}:${port}: /reading and /stream pay ${config.merchant}`)
  })

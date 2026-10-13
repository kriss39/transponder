// A local MPP service on Moderato testnet, built with the reference SDK.
//
//   node server.mjs            # http://127.0.0.1:8402/reading costs 0.01 AlphaUSD
//   HOST=0.0.0.0 node server.mjs   # reachable from a board on the same network
//
// Run setup.mjs first: it writes the merchant address this server charges to.

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import http from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Mppx, tempo } from 'mppx/server'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const config = JSON.parse(readFileSync(join(root, '.testnet', 'server.json'), 'utf8'))
const host = process.env.HOST ?? '127.0.0.1'
const port = Number(process.env.PORT ?? 8402)

const mppx = Mppx.create({
  methods: [tempo.charge({ currencies: [config.token], recipient: config.merchant, testnet: true })],
  secretKey: randomBytes(32).toString('hex'),
})
const charge = mppx.charge({ amount: '0.01', description: 'One sensor reading' })

async function handle(request) {
  const url = new URL(request.url)
  if (url.pathname !== '/reading') return new Response('not found\n', { status: 404 })
  const result = await charge(request)
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
    console.log(`MPP test service on http://${host}:${port}/reading (0.01 AlphaUSD to ${config.merchant})`)
  })

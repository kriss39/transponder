// Prepares a Moderato testnet run with throwaway accounts.
//
//   cd tools/testnet && npm install && node setup.mjs
//
// It creates (or reuses) .testnet/state.json at the repository root with:
//   - an owner account (secp256k1), funded from the faucet,
//   - a merchant address that the local server charges to,
//   - the device's P-256 key, authorized on the owner as an access key with
//     a 5 AlphaUSD budget, a 7-day expiry and transferWithMemo to the
//     merchant only.
// Then it writes .testnet/device.env for the C demo and .testnet/server.json
// for server.mjs. Everything here is testnet-only; never put real keys in it.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { encodeFunctionData, formatUnits, parseAbi, parseUnits } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { prepareTransactionRequest } from 'viem/actions'
import { tempoModerato } from 'viem/chains'
import { Account, createClient, P256 } from 'viem/tempo'

const RPC = 'https://rpc.moderato.tempo.xyz'
const ALPHA_USD = '0x20c0000000000000000000000000000000000001'
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const dir = join(root, '.testnet')
const statePath = join(dir, 'state.json')

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const body = await res.json()
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`)
  return body.result
}

mkdirSync(dir, { recursive: true, mode: 0o700 })
const state = existsSync(statePath)
  ? JSON.parse(readFileSync(statePath, 'utf8'))
  : {
      ownerPrivateKey: generatePrivateKey(),
      merchantPrivateKey: generatePrivateKey(),
      devicePrivateKey: P256.randomPrivateKey(),
    }
writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 })

const owner = Account.fromSecp256k1(state.ownerPrivateKey)
const merchant = privateKeyToAccount(state.merchantPrivateKey).address
const device = Account.fromP256(state.devicePrivateKey, { access: owner })
const client = createClient({ account: owner, chain: tempoModerato, feeToken: ALPHA_USD })

console.log('owner   ', owner.address)
console.log('merchant', merchant)
console.log('device key', device.accessKeyAddress)

// 1. Test funds for the owner.
const balance = async () =>
  (await client.token.getBalance({ account: owner.address, token: ALPHA_USD })).amount
let funds = await balance()
if (funds < parseUnits('1', 6)) {
  console.log('funding the owner from the faucet...')
  await rpc('tempo_fundAddress', [owner.address])
  for (let i = 0; i < 30 && funds < parseUnits('1', 6); i++) {
    await new Promise((r) => setTimeout(r, 1000))
    funds = await balance()
  }
}
console.log('owner AlphaUSD', formatUnits(funds, 6))
if (funds < parseUnits('1', 6)) throw new Error('the faucet did not fund the owner')

// 2. Authorize the device key, once.
const metadata = await client.accessKey.getMetadata({ accessKey: device }).catch(() => undefined)
const active = metadata && !metadata.isRevoked && metadata.expiry > BigInt(Math.floor(Date.now() / 1000))
if (!active) {
  console.log('authorizing the device key...')
  const { receipt } = await client.accessKey.authorizeSync({
    accessKey: device,
    expiry: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    limits: [{ token: ALPHA_USD, limit: parseUnits('5', 6), period: 0 }],
    scopes: [
      {
        address: ALPHA_USD,
        selector: 'transferWithMemo(address,uint256,bytes32)',
        recipients: [merchant],
      },
    ],
  })
  console.log('authorized in', receipt.transactionHash)
}
const remaining = await client.accessKey.getRemainingLimit({ accessKey: device, token: ALPHA_USD })
console.log('device budget left', formatUnits(remaining.remaining, 6), 'AlphaUSD')

// 3. Gas and fee values for one payment, estimated as the device would send it.
const deviceClient = createClient({ account: device, chain: tempoModerato, feeToken: ALPHA_USD })
const prepared = await prepareTransactionRequest(deviceClient, {
  calls: [
    {
      to: ALPHA_USD,
      data: encodeFunctionData({
        abi: parseAbi(['function transferWithMemo(address to, uint256 amount, bytes32 memo)']),
        functionName: 'transferWithMemo',
        args: [merchant, 10000n, `0x${'00'.repeat(32)}`],
      }),
    },
  ],
  nonceKey: 'expiring',
  validBefore: Math.floor(Date.now() / 1000) + 25,
})
// mppx adds 5000 to the estimate for signature and access-key checks; add a
// little more because the device signs as a Keychain access key.
const gas = prepared.gas + 20000n
console.log('estimated gas', prepared.gas, '-> using', gas)
console.log('fees', prepared.maxFeePerGas, prepared.maxPriorityFeePerGas)

writeFileSync(
  join(dir, 'device.env'),
  [
    `TRP_CHAIN_ID=${tempoModerato.id}`,
    `TRP_OWNER=${owner.address}`,
    `TRP_DEVICE_KEY=${state.devicePrivateKey}`,
    `TRP_FEE_TOKEN=${ALPHA_USD}`,
    `TRP_GAS=${gas}`,
    `TRP_MAX_FEE=${prepared.maxFeePerGas * 2n}`,
    `TRP_PRIORITY_FEE=${prepared.maxPriorityFeePerGas ?? 0n}`,
    '',
  ].join('\n'),
  { mode: 0o600 },
)
writeFileSync(
  join(dir, 'server.json'),
  JSON.stringify({ merchant, token: ALPHA_USD }, null, 2),
)
console.log('wrote .testnet/device.env and .testnet/server.json')

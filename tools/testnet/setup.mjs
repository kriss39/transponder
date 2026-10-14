// Prepares a Moderato testnet run with throwaway accounts.
//
//   cd tools/testnet && npm install && node setup.mjs
//
// It creates (or reuses) .testnet/state.json at the repository root with:
//   - an owner account (secp256k1), funded from the faucet,
//   - a merchant address that the local server charges to,
//   - the device's P-256 key, authorized on the owner as an access key with
//     a 5 AlphaUSD budget, a 7-day expiry and transferWithMemo to the
//     merchant only,
//   - a second P-256 key for sessions, allowed only to open and top up
//     channels in the TIP-1034 escrow precompile, with a 1 AlphaUSD budget.
// Secure Enclave keys (.testnet/enclave.pub, .testnet/enclave-session.pub)
// get the same grants. Then it writes .testnet/device.env for the C demo and
// .testnet/server.json for server.mjs. Everything here is testnet-only; never put real keys in it.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { encodeFunctionData, formatUnits, parseAbi, parseUnits } from 'viem'
import { generatePrivateKey, privateKeyToAccount, publicKeyToAddress } from 'viem/accounts'
import { prepareTransactionRequest } from 'viem/actions'
import { tempoModerato } from 'viem/chains'
import { Account, createClient, P256 } from 'viem/tempo'

const RPC = 'https://rpc.moderato.tempo.xyz'
const ALPHA_USD = '0x20c0000000000000000000000000000000000001'
const ESCROW = '0x4d50500000000000000000000000000000000000'
const ZERO = '0x0000000000000000000000000000000000000000'
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
state.sessionPrivateKey ??= P256.randomPrivateKey()
writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 })

const owner = Account.fromSecp256k1(state.ownerPrivateKey)
const merchant = privateKeyToAccount(state.merchantPrivateKey).address
const device = Account.fromP256(state.devicePrivateKey, { access: owner })
const sessionDevice = Account.fromP256(state.sessionPrivateKey, { access: owner })
const client = createClient({ account: owner, chain: tempoModerato, feeToken: ALPHA_USD })

console.log('owner   ', owner.address)
console.log('merchant', merchant)
console.log('device key', device.accessKeyAddress)
console.log('session key', sessionDevice.accessKeyAddress)

// 1. Test funds for the owner, and for the merchant, which pays the fee to
// close session channels.
async function fund(address, label) {
  const balance = async () => (await client.token.getBalance({ account: address, token: ALPHA_USD })).amount
  let funds = await balance()
  if (funds < parseUnits('1', 6)) {
    console.log(`funding the ${label} from the faucet...`)
    await rpc('tempo_fundAddress', [address])
    for (let i = 0; i < 30 && funds < parseUnits('1', 6); i++) {
      await new Promise((r) => setTimeout(r, 1000))
      funds = await balance()
    }
  }
  console.log(`${label} AlphaUSD`, formatUnits(funds, 6))
  if (funds < parseUnits('1', 6)) throw new Error(`the faucet did not fund the ${label}`)
}
await fund(owner.address, 'owner')
await fund(merchant, 'merchant')

// 2. Authorize each key once, then report what is left of its budget.
const chargeScopes = [
  { address: ALPHA_USD, selector: 'transferWithMemo(address,uint256,bytes32)', recipients: [merchant] },
]
// open(address,address,address,uint96,bytes32,address) and
// topUp((address,address,address,address,bytes32,address,bytes32),uint96).
const sessionScopes = [
  { address: ESCROW, selector: '0xedc53b00' },
  { address: ESCROW, selector: '0xdc48471e' },
]
async function authorize(accessKey, label, scopes, limit) {
  const meta = await client.accessKey.getMetadata({ accessKey }).catch(() => undefined)
  const live = meta && !meta.isRevoked && meta.expiry > BigInt(Math.floor(Date.now() / 1000))
  if (!live) {
    console.log(`authorizing the ${label}...`)
    const { receipt } = await client.accessKey.authorizeSync({
      accessKey,
      expiry: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
      limits: [{ token: ALPHA_USD, limit: parseUnits(limit, 6), period: 0 }],
      scopes,
    })
    console.log('authorized in', receipt.transactionHash)
  }
  const left = await client.accessKey.getRemainingLimit({ accessKey, token: ALPHA_USD })
  console.log(`${label} budget left`, formatUnits(left.remaining, 6), 'AlphaUSD')
}
await authorize(device, 'device key', chargeScopes, '5')
await authorize(sessionDevice, 'session key', sessionScopes, '1')

// Secure Enclave keys (made by `./build/enclave-key create <file>`) get the
// same grants. Only their public keys are known here; the private keys never
// leave the Mac's enclave.
function enclaveKey(name) {
  const pub = join(dir, `${name}.pub`)
  if (!existsSync(pub)) return undefined
  const xy = readFileSync(pub, 'utf8').trim().replace(/^0x/, '')
  return { accessKeyAddress: publicKeyToAddress(`0x04${xy}`), keyType: 'p256', path: join(dir, `${name}.key`) }
}
const enclave = enclaveKey('enclave')
if (enclave) {
  console.log('enclave key', enclave.accessKeyAddress)
  await authorize(enclave, 'enclave key', chargeScopes, '5')
}
const enclaveSession = enclaveKey('enclave-session')
if (enclaveSession) {
  console.log('enclave session key', enclaveSession.accessKeyAddress)
  await authorize(enclaveSession, 'enclave session key', sessionScopes, '1')
}

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

// The same for opening a channel; a top-up costs about as much.
const sessionClient = createClient({ account: sessionDevice, chain: tempoModerato, feeToken: ALPHA_USD })
const preparedOpen = await prepareTransactionRequest(sessionClient, {
  calls: [
    {
      to: ESCROW,
      data: encodeFunctionData({
        abi: parseAbi([
          'function open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner)',
        ]),
        functionName: 'open',
        args: [merchant, ZERO, ALPHA_USD, 3000n, `0x${'11'.repeat(32)}`, sessionDevice.accessKeyAddress],
      }),
    },
  ],
  nonceKey: 'expiring',
  validBefore: Math.floor(Date.now() / 1000) + 25,
})
const sessionGas = preparedOpen.gas + 50000n
console.log('estimated open gas', preparedOpen.gas, '-> using', sessionGas)

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
    ...(enclave ? [`TRP_ENCLAVE_KEY="${enclave.path}"`] : []),
    `TRP_SESSION_KEY=${state.sessionPrivateKey}`,
    `TRP_SESSION_GAS=${sessionGas}`,
    ...(enclaveSession ? [`TRP_SESSION_ENCLAVE_KEY="${enclaveSession.path}"`] : []),
    '',
  ].join('\n'),
  { mode: 0o600 },
)
writeFileSync(
  join(dir, 'server.json'),
  JSON.stringify({ merchant, token: ALPHA_USD }, null, 2),
)
console.log('wrote .testnet/device.env and .testnet/server.json')

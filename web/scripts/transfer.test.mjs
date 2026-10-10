import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const wasmPath = new URL('../public/remotesync_protocol.wasm', import.meta.url)
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const accountId = 'acc_aaaaaaaaaaaaaaaaaaaaaaaaaa'
const syncKeyHex = '11'.repeat(32)
const seedHex = '22'.repeat(32)

async function load() {
  let wasm
  const env = { rs_random: (pointer, length) => { crypto.getRandomValues(new Uint8Array(wasm.memory.buffer, pointer, length)) } }
  wasm = (await WebAssembly.instantiate(await readFile(wasmPath), { env })).instance.exports
  return payload => {
    const input = encoder.encode(JSON.stringify(payload))
    const pointer = wasm.rs_alloc(input.length)
    new Uint8Array(wasm.memory.buffer, pointer, input.length).set(input)
    const output = wasm.rs_process(pointer, input.length)
    const length = wasm.rs_output_len()
    const text = decoder.decode(new Uint8Array(wasm.memory.buffer, output, length).slice())
    wasm.rs_free_output(output, length)
    wasm.rs_dealloc(pointer, input.length)
    return JSON.parse(text)
  }
}

test('a key sent with the displayed code opens only on the receiving device', async () => {
  const call = await load()
  const { epk } = call({ op: 'transferPublic', seedHex })
  const transferId = 'ABCDEFGH'
  const { code } = call({ op: 'transferCode', seedHex, transferId })
  assert.equal(call({ op: 'transferParse', code }).transferId, transferId)

  const { blob } = call({ op: 'transferSeal', syncKeyHex, code, epk, accountId })
  assert.equal(call({ op: 'transferOpen', seedHex, accountId, transferId, blob }).syncKeyHex, syncKeyHex)
  assert.ok(call({ op: 'transferOpen', seedHex: '33'.repeat(32), accountId, transferId, blob }).error)
  assert.ok(call({ op: 'transferOpen', seedHex, accountId: 'acc_bbbbbbbbbbbbbbbbbbbbbbbbbb', transferId, blob }).error)
})

test('a substituted public key is refused before anything is encrypted', async () => {
  const call = await load()
  const { code } = call({ op: 'transferCode', seedHex, transferId: 'ABCDEFGH' })
  const attacker = call({ op: 'transferPublic', seedHex: '44'.repeat(32) }).epk
  assert.ok(call({ op: 'transferSeal', syncKeyHex, code, epk: attacker, accountId }).error)
})

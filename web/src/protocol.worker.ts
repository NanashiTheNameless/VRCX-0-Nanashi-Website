type RequestMessage = { id: number; type: 'unlock' | 'forget' | 'open' | 'live' | 'transferStart' | 'transferCode' | 'transferReceive' | 'transferParse' | 'transferSend' | 'manifestInfo' | 'manifestRetention'; payload?: unknown }

type WasmExports = {
  memory: WebAssembly.Memory
  rs_alloc: (length: number) => number
  rs_dealloc: (pointer: number, length: number) => void
  rs_process: (pointer: number, length: number) => number
  rs_output_len: () => number
  rs_free_output: (pointer: number, length: number) => void
}

let wasm: Promise<WasmExports> | null = null
let memory: WebAssembly.Memory | null = null
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const workerScope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<RequestMessage>) => void) | null
  postMessage: (message: unknown) => void
}
let syncKeyHex = ''
let transferSeedHex = ''

async function loadWasm(): Promise<WasmExports> {
  if (!wasm) wasm = WebAssembly.instantiate(await (await fetch('/remotesync_protocol.wasm')).arrayBuffer(), {
    env: { rs_random: (pointer: number, length: number) => { crypto.getRandomValues(new Uint8Array(memory!.buffer, pointer, length)) } },
  }).then(result => { memory = (result.instance.exports as unknown as WasmExports).memory; return result.instance.exports as unknown as WasmExports })
  return wasm
}

function openBatch(exports: WasmExports, payload: unknown, failure = 'Vault verification failed') {
  const input = encoder.encode(JSON.stringify(payload))
  const inputPointer = exports.rs_alloc(input.length)
  new Uint8Array(exports.memory.buffer, inputPointer, input.length).set(input)
  const outputPointer = exports.rs_process(inputPointer, input.length)
  const outputLength = exports.rs_output_len()
  const output = new Uint8Array(exports.memory.buffer, outputPointer, outputLength).slice()
  exports.rs_free_output(outputPointer, outputLength)
  exports.rs_dealloc(inputPointer, input.length)
  const parsed = JSON.parse(decoder.decode(output))
  if (parsed?.error) throw new Error(`${failure}: ${parsed.error}`)
  return parsed
}

workerScope.onmessage = async (event: MessageEvent<RequestMessage>) => {
  try {
    if (event.data.type === 'unlock') {
      const key = String(event.data.payload ?? '').trim()
      if (!/^[0-9a-fA-F]{64}$/.test(key)) throw new Error('The sync key must be exactly 64 hexadecimal characters.')
      syncKeyHex = key
      workerScope.postMessage({ id: event.data.id, result: true })
      return
    }
    if (event.data.type === 'forget') {
      syncKeyHex = ''
      workerScope.postMessage({ id: event.data.id, result: true })
      return
    }
    const exports = await loadWasm()
    const transfer = (op: string, fields: object) => openBatch(exports, { op, ...fields }, 'Key transfer failed')
    const reply = (result: unknown) => workerScope.postMessage({ id: event.data.id, result })
    const input = (event.data.payload ?? {}) as Record<string, string>
    if (event.data.type === 'transferStart') {
      transferSeedHex = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('')
      return reply(transfer('transferPublic', { seedHex: transferSeedHex }))
    }
    if (event.data.type === 'transferCode') return reply(transfer('transferCode', { seedHex: transferSeedHex, transferId: input.transferId }))
    if (event.data.type === 'transferReceive') {
      syncKeyHex = transfer('transferOpen', { seedHex: transferSeedHex, ...input }).syncKeyHex
      transferSeedHex = ''
      return reply(true)
    }
    if (event.data.type === 'transferParse') return reply(transfer('transferParse', { code: input.code }))
    if (!syncKeyHex) throw new Error('Unlock your key in this tab first.')
    if (event.data.type === 'transferSend') return reply(transfer('transferSeal', { syncKeyHex, ...input }))
    if (event.data.type === 'manifestInfo' || event.data.type === 'manifestRetention') return reply(openBatch(exports, { op: event.data.type, syncKeyHex, ...(event.data.payload as object) }, 'Vault settings could not be read'))
    const payload = { ...(event.data.payload as object), syncKeyHex }
    if (event.data.type === 'live') Object.assign(payload, { op: 'openLive' })
    workerScope.postMessage({ id: event.data.id, result: openBatch(exports, payload) })
  } catch (error) {
    workerScope.postMessage({ id: event.data.id, error: error instanceof Error ? error.message : String(error) })
  }
}

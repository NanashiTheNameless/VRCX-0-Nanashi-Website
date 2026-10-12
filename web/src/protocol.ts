import { startProtocolWorker } from './workers'

type ChunkInput = { chunkId: string; blob: string }
type OpenBatch = { vaultId: string; manifestSeq: number; highestManifestSeq: number | null; manifest: string; chunks: ChunkInput[] }

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, { resolve: (value: any[]) => void; reject: (error: Error) => void }>()

function getWorker() {
  if (!worker) {
    worker = startProtocolWorker()
    worker.onmessage = (event: MessageEvent<{ id: number; result?: any; error?: string }>) => {
      const task = pending.get(event.data.id)
      if (!task) return
      pending.delete(event.data.id)
      if (event.data.error) task.reject(new Error(event.data.error))
      else task.resolve(event.data.result ?? [])
    }
    worker.onerror = event => {
      for (const task of pending.values()) task.reject(new Error(event.message || 'The protocol worker stopped.'))
      pending.clear()
      worker?.terminate()
      worker = null
    }
  }
  return worker
}

function callWorker(type: 'unlock' | 'forget' | 'open' | 'live' | 'transferStart' | 'transferCode' | 'transferReceive' | 'transferParse' | 'transferSend' | 'manifestInfo' | 'manifestRetention' | 'collectorSealUnlock', payload?: unknown): Promise<any> {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ id, type, payload })
  })
}

export async function unlockProtocolWorker(syncKeyHex: string) { await callWorker('unlock', syncKeyHex) }
export async function forgetProtocolWorker() { if (worker) { await callWorker('forget'); stopProtocolWorker() } }
export function verifyAndOpenBatch(input: OpenBatch): Promise<any[]> { return callWorker('open', input) }
export function verifyAndOpenLive(input: { vaultId: string; manifestSeq: number; highestManifestSeq: number | null; manifest: string; liveSeq: number; blob: string }): Promise<any> { return callWorker('live', input) }

export const transferStart = (): Promise<{ epk: string }> => callWorker('transferStart')
export const transferCode = (transferId: string): Promise<{ code: string }> => callWorker('transferCode', { transferId })
export const transferReceive = (input: { accountId: string; transferId: string; blob: string }): Promise<unknown> => callWorker('transferReceive', input)
export const transferParse = (code: string): Promise<{ transferId: string }> => callWorker('transferParse', { code })
export const transferSend = (input: { accountId: string; code: string; epk: string }): Promise<{ blob: string }> => callWorker('transferSend', input)

export type ManifestInfo = { subject: { vrchatUserId: string; displayName: string } | null; retention: { maxAgeDays: number | null; keepBelowLimitMarginPct: number | null }; signers: { label: string; kind: string }[] }
type ManifestInput = { vaultId: string; manifestSeq: number; manifest: string }
export const manifestInfo = (input: ManifestInput): Promise<ManifestInfo> => callWorker('manifestInfo', input)
export const manifestRetention = (input: ManifestInput & { maxAgeDays: number | null; keepBelowLimitMarginPct: number | null }): Promise<{ manifest: string; manifestSeq: number }> => callWorker('manifestRetention', input)
export const collectorSealUnlock = (input: { accountId: string; vaultId: string; unlockKey: string; vrchatUserId: string; authCookie: string; twoFactorCookie: string; expiresAt: number | null; intervalSeconds: number }): Promise<{ sealed: string }> => callWorker('collectorSealUnlock', input)

export function stopProtocolWorker() {
  worker?.terminate()
  worker = null
  for (const task of pending.values()) task.reject(new Error('Protocol worker stopped.'))
  pending.clear()
}

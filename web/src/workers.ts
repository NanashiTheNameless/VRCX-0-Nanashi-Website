import pbkdf2WorkerUrl from 'altcha/workers/pbkdf2?worker&url'
import protocolWorkerUrl from './protocol.worker.ts?worker&url'

function sameOriginAsset(url: string) {
  const parsed = new URL(url, location.href)
  if (parsed.origin !== location.origin || !parsed.pathname.startsWith('/assets/')) throw new TypeError('Refused to start a worker from an unexpected address.')
  return parsed.href
}

type ScriptUrlPolicy = { createScriptURL: (url: string) => unknown }
type PolicyFactory = { createPolicy: (name: string, rules: { createScriptURL: (url: string) => string }) => ScriptUrlPolicy }

const policy = (window as unknown as { trustedTypes?: PolicyFactory }).trustedTypes?.createPolicy('remotesync-worker', { createScriptURL: sameOriginAsset })

function start(url: string) {
  return new Worker((policy ? policy.createScriptURL(url) : sameOriginAsset(url)) as string, { type: 'module' })
}

export const startProtocolWorker = () => start(protocolWorkerUrl)
export const startPbkdf2Worker = () => start(pbkdf2WorkerUrl)

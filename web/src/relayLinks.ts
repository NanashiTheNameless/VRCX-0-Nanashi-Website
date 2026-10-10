const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
const WORLD_ID = new RegExp(`^wrld_${UUID}$`, 'i')
const AVATAR_ID = new RegExp(`^avtr_${UUID}$`, 'i')
const IMAGE_HOSTS = new Set(['api.vrchat.cloud', 'assets.vrchat.com'])
const PREVIEW_LIMIT = 200

const APP_SCHEME = 'vrcx-0-nanashi'

export type RelayPreview = { name: string; author: string; imageUrl: string }
export type RelayTarget =
  | { kind: 'world' | 'avatar'; id: string; preview: RelayPreview }
  | { kind: 'instance'; worldId: string; instanceId: string; shortName: string; launchToken: string }

const hasControl = (value: string) =>
  Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code < 32 || (code >= 127 && code <= 159)
  })

function limit(value: string | null) {
  return Array.from((value ?? '').trim()).slice(0, PREVIEW_LIMIT).join('')
}

function previewImage(value: string | null) {
  if (!value || Array.from(value).length > PREVIEW_LIMIT) return ''
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && IMAGE_HOSTS.has(url.hostname) ? url.toString() : ''
  } catch {
    return ''
  }
}

export function parsePreview(hash: string): RelayPreview {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  return { name: limit(params.get('n')), author: limit(params.get('a')), imageUrl: previewImage(params.get('i')) }
}

function single(params: URLSearchParams, key: string, required: boolean) {
  const values = params.getAll(key)
  if (values.length > 1 || (required && values.length !== 1)) return null
  return values[0] ?? ''
}

export function parseRelayLocation(pathname: string, search: string, hash: string): RelayTarget | null {
  const parts = pathname.split('/')
  if (parts.length !== 4 || parts[0] !== '' || parts[1] !== 'open') return null
  let id: string
  try {
    id = decodeURIComponent(parts[3])
  } catch {
    return null
  }
  if (parts[2] === 'world') return WORLD_ID.test(id) ? { kind: 'world', id, preview: parsePreview(hash) } : null
  if (parts[2] === 'avatar') return AVATAR_ID.test(id) ? { kind: 'avatar', id, preview: parsePreview(hash) } : null
  if (parts[2] !== 'instance' || !WORLD_ID.test(id)) return null

  const params = new URLSearchParams(search)
  const instanceId = single(params, 'instanceId', true)
  const shortName = single(params, 'shortName', false)
  const launchToken = single(params, 'launchToken', false)
  if (!instanceId || shortName === null || launchToken === null) return null
  if (/[\s:/?#&]/.test(instanceId) || /\s/.test(shortName + launchToken)) return null
  if (hasControl(instanceId + shortName + launchToken)) return null
  return { kind: 'instance', worldId: id, instanceId, shortName, launchToken }
}

export function appLink(target: RelayTarget) {
  if (target.kind !== 'instance') return `${APP_SCHEME}://${target.kind}/open?id=${encodeURIComponent(target.id)}`
  const params = new URLSearchParams({ id: target.worldId, instanceId: target.instanceId })
  if (target.shortName) params.set('shortName', target.shortName)
  if (target.launchToken) params.set('launchToken', target.launchToken)
  return `${APP_SCHEME}://instance/open?${params}`
}

export function vrchatLink(target: RelayTarget) {
  if (target.kind !== 'instance') return `https://vrchat.com/home/${target.kind}/${encodeURIComponent(target.id)}`
  const params = new URLSearchParams({ worldId: target.worldId, instanceId: target.instanceId })
  if (target.shortName) params.set('shortName', target.shortName)
  return `https://vrchat.com/home/launch?${params}`
}

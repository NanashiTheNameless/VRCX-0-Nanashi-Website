type Config = { apiOrigin: string }

export const configPromise = fetch('/config.json').then(r => r.json() as Promise<Config>)
export const tokenKey = 'remotesync.session'
export const getToken = () => sessionStorage.getItem(tokenKey) ?? localStorage.getItem(tokenKey)

export async function apiFetch(path: string, init: RequestInit = {}) {
  const config = await configPromise
  const headers = new Headers(init.headers)
  const token = getToken()
  if (token) headers.set('authorization', `Bearer ${token}`)
  return fetch(`${config.apiOrigin}/web/v1${path}`, { ...init, headers })
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('content-type', 'application/json')
  const response = await apiFetch(path, { ...init, headers })
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: `Request failed (${response.status})` }))
    throw new Error(error.message ?? error.error?.message ?? `Request failed (${response.status})`)
  }
  if (response.status === 204 || response.status === 202) return undefined as T
  return await response.json() as T
}

export async function requestBinary(path: string) {
  const response = await apiFetch(path)
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: `Request failed (${response.status})` }))
    throw new Error(error.message ?? error.error?.message ?? `Request failed (${response.status})`)
  }
  return response
}

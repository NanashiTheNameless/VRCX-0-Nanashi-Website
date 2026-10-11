type Config = { apiOrigin: string }

export const configPromise = fetch('/config.json').then(r => r.json() as Promise<Config>)
export const tokenKey = 'remotesync.session'
export const getToken = () => sessionStorage.getItem(tokenKey) ?? localStorage.getItem(tokenKey)

export class ApiError extends Error {
  status: number
  code: string
  constructor(message: string, status: number, code = '') {
    super(message)
    this.status = status
    this.code = code
  }
}

export async function failure(response: Response) {
  const body = await response.json().catch(() => null)
  const detail = body?.error ?? body
  const code = typeof detail?.code === 'string' ? detail.code : ''
  const message = code === 'reauth_required' ? 'Enter a verification code first.' : detail?.message ?? `Request failed (${response.status})`
  return new ApiError(message, response.status, code)
}

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
  if (!response.ok) throw await failure(response)
  if (response.status === 204 || response.status === 202) return undefined as T
  return await response.json() as T
}

export async function requestBinary(path: string) {
  const response = await apiFetch(path)
  if (!response.ok) throw await failure(response)
  return response
}

export async function publicGet<T>(path: string): Promise<T> {
  const config = await configPromise
  const response = await fetch(`${config.apiOrigin}/public/v1${path}`)
  if (!response.ok) throw new ApiError(response.status === 404 ? 'This page was not found.' : `Could not load page (${response.status})`, response.status)
  return await response.json() as T
}

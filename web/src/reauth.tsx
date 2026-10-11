import { useState, useSyncExternalStore } from 'react'
import { ApiError, request } from './api'

type Shared = { until: number; method: string | null; code: string; sent: boolean }

const WINDOW_MS = 9 * 60 * 1000
const listeners = new Set<() => void>()
let shared: Shared = { until: 0, method: null, code: '', sent: false }
let timer: ReturnType<typeof setTimeout> | undefined

function update(patch: Partial<Shared>) {
  shared = { ...shared, ...patch }
  for (const listener of listeners) listener()
}

function setVerifiedUntil(value: number) {
  clearTimeout(timer)
  if (value > Date.now()) timer = setTimeout(() => setVerifiedUntil(0), value - Date.now())
  update({ until: value })
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function forgetVerification() {
  clearTimeout(timer)
  update({ until: 0, method: null, code: '', sent: false })
}

export function noteReauthFailure(error: unknown) {
  if (error instanceof ApiError && error.code === 'reauth_required') forgetVerification()
}

export function useReauth(defaultMethod: string | null) {
  const state = useSyncExternalStore(subscribe, () => shared)
  const method = state.method ?? (defaultMethod === 'email' ? 'email' : 'totp')
  const { code, sent, until } = state
  const [sending, setSending] = useState(false)
  const [problem, setProblem] = useState('')
  const verified = until > Date.now()

  const confirm = async () => {
    if (shared.until > Date.now()) return
    if (!code.trim()) throw new Error('Enter a verification code first.')
    await request('/reauth', { method: 'POST', body: JSON.stringify({ method, code: code.trim() }) })
    update({ code: '', sent: false })
    setVerifiedUntil(Date.now() + WINDOW_MS)
  }
  const sendCode = async () => {
    setSending(true)
    setProblem('')
    try {
      await request('/reauth/email-code', { method: 'POST' })
      update({ sent: true })
    } catch (error) {
      setProblem((error as Error).message)
    } finally {
      setSending(false)
    }
  }

  const fields = verified ? (
    <p className="reauth verified">Verified. Changes on this account are unlocked for a few minutes.</p>
  ) : (
    <div className="reauth">
      <label>
        Verification method
        <select value={method} onChange={event => { update({ method: event.target.value, code: '', sent: false }); setProblem('') }}>
          <option value="totp">Authenticator app</option>
          <option value="email">Email code</option>
          <option value="recovery">Recovery code</option>
        </select>
      </label>
      {method === 'email' && (
        <button type="button" disabled={sending} onClick={() => void sendCode()}>
          {sending ? 'Sending...' : sent ? 'Send another email code' : 'Send email code'}
        </button>
      )}
      {problem && <div className="alert error">{problem}</div>}
      <label>
        {method === 'totp' ? 'Authenticator code' : method === 'email' ? 'Email verification code' : 'Recovery code'}
        <input
          autoComplete={method === 'recovery' ? 'off' : 'one-time-code'}
          inputMode={method === 'recovery' ? 'text' : 'numeric'}
          value={code}
          onChange={event => update({ code: event.target.value })}
        />
      </label>
    </div>
  )
  const note = verified ? fields : <p className="reauth muted">Uses the verification code entered at the top of this page.</p>
  return { confirm, fields, note, ready: verified || code.trim().length > 0 }
}

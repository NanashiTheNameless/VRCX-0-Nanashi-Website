import React, { useCallback, useEffect, useState } from 'react'
import { apiFetch, apiOriginFetch, failure, request } from './api'
import { manifestInfo, collectorSealUnlock } from './protocol'
import { formatBytes } from './site'

type Vault = { vaultId: string; manifestSeq: number; maxSeq: number; usageBytes: number }
type Capabilities = { available: boolean; unlockKey: string } | null
type Status = { state: string; sinceMs?: number | null; lastChunkAtMs?: number | null; lastError?: string | null }
type VaultRow = { vault: Vault; status: Status | null; error: string }
const decode = (text: string) => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0))
const when = (ms?: number | null) => ms ? new Date(ms).toLocaleString() : 'Never'

export function CollectorPage({ accountId, allowed, unlocked, act }: { accountId: string; allowed: boolean; unlocked: boolean; act: (f: () => Promise<void>) => Promise<void> }) {
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null)
  const [rows, setRows] = useState<VaultRow[]>([])
  const [selected, setSelected] = useState('')
  const [vrchatUserId, setVrchatUserId] = useState('')
  const [authCookie, setAuthCookie] = useState('')
  const [twoFactorCookie, setTwoFactorCookie] = useState('')
  const [days, setDays] = useState('7')
  const [forever, setForever] = useState(false)
  const [interval, setInterval] = useState('300')
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true); setLoadError('')
    try {
      const [caps, vaults] = await Promise.all([apiOriginFetch('/web/v1/collector/capabilities').then(async response => { if (!response.ok) throw await failure(response); return await response.json() as Capabilities }), request<Vault[]>('/vaults')])
      setCapabilities(caps)
      setSelected(current => vaults.some(v => v.vaultId === current) ? current : vaults[0]?.vaultId ?? '')
      const next = await Promise.all(vaults.map(async vault => {
        try {
          const status = await request<Status>(`/vaults/${encodeURIComponent(vault.vaultId)}/collector`)
          return { vault, status, error: '' }
        } catch (cause) { return { vault, status: null, error: (cause as Error).message } }
      }))
      setRows(next)
    } catch (cause) { setLoadError((cause as Error).message) }
    finally { setLoading(false) }
  }, [])
  useEffect(() => { if (allowed) void refresh() }, [allowed, refresh])

  const start = (vault: Vault) => act(async () => {
    if (!unlocked) throw new Error('Unlock your sync key under Security before starting the collector.')
    const cap = capabilities
    if (!cap?.available) throw new Error('The collector service is unavailable on this server.')
    if (!authCookie.trim()) throw new Error('Enter the VRChat auth cookie.')
    const expiryDays = Number(days), intervalSeconds = Number(interval)
    if (!forever && (!Number.isInteger(expiryDays) || expiryDays < 1 || expiryDays > 30)) throw new Error('Session duration must be from 1 to 30 days.')
    if (!Number.isInteger(intervalSeconds) || intervalSeconds < 60 || intervalSeconds > 900) throw new Error('Sync interval must be from 60 to 900 seconds.')
    let userId = vrchatUserId.trim()
    if (vault.manifestSeq > 0) {
      const response = await apiFetch(`/vaults/${encodeURIComponent(vault.vaultId)}/manifest`)
      if (response.ok) {
        const blob = new Uint8Array(await response.arrayBuffer())
        const encoded = btoa(Array.from(blob, byte => String.fromCharCode(byte)).join('')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
        const info = await manifestInfo({ vaultId: vault.vaultId, manifestSeq: vault.manifestSeq, manifest: encoded })
        userId = info.subject?.vrchatUserId || userId
      }
    }
    if (!userId) throw new Error('Enter your VRChat user ID; it is not stored in this vault manifest.')
    const sealed = await collectorSealUnlock({ accountId, vaultId: vault.vaultId, unlockKey: cap.unlockKey, vrchatUserId: userId, authCookie: authCookie.trim(), twoFactorCookie: twoFactorCookie.trim(), expiresAt: forever ? null : Date.now() + expiryDays * 24 * 60 * 60 * 1000, intervalSeconds })
    const response = await apiFetch(`/vaults/${encodeURIComponent(vault.vaultId)}/collector/unlock`, { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: decode(sealed.sealed).buffer as ArrayBuffer })
    if (!response.ok) throw await failure(response)
    setAuthCookie(''); setTwoFactorCookie(''); await refresh()
  })
  const lock = (vault: Vault) => act(async () => { await request(`/vaults/${encodeURIComponent(vault.vaultId)}/collector/lock`, { method: 'POST' }); await refresh() })

  if (!allowed) return <article className="card"><h2>Collector access unavailable</h2><p className="muted">An administrator must enable collector access for this account.</p></article>
  const chosen = rows.find(row => row.vault.vaultId === selected)?.vault
  return <>
    <article className="card"><div className="section-heading"><div><h2>Remote collector</h2><p className="muted">Control the collector for each vault. VRChat cookies are sealed to this server’s collector key in the protocol worker before they are sent.</p></div><button disabled={loading} onClick={() => void refresh()}>{loading ? 'Refreshing…' : 'Refresh'}</button></div>
      {loadError && <div className="alert error">{loadError}</div>}
      <p>Service: <strong>{capabilities?.available ? 'Available' : capabilities ? 'Unavailable' : 'Checking'}</strong>{capabilities?.available === false && <span className="muted"> · Collector runtime is not ready on this server.</span>}</p>
      {rows.length === 0 && !loading ? <p className="muted">No vaults are available. Create or pair a vault first.</p> : <div className="envelope-list">{rows.map(({ vault, status, error }) => <article className="card" key={vault.vaultId}><div className="section-heading"><div><b>Vault {vault.vaultId}</b><small>{formatBytes(vault.usageBytes)} · {vault.maxSeq} history records</small></div><span className={`pill ${status?.state ?? 'unknown'}`}>{status?.state ?? (error ? 'Unavailable' : 'Unknown')}</span></div>
        <p className="muted">Last upload: {when(status?.lastChunkAtMs)}{status?.lastError ? ` · ${status.lastError}` : error ? ` · ${error}` : ''}</p>
        {status?.state === 'running' ? <button className="danger" onClick={() => lock(vault)}>Lock collector</button> : <button onClick={() => setSelected(vault.vaultId)}>Configure session</button>}
      </article>)}</div>}
    </article>
    <article className="card"><h2>Start a collector session</h2><p className="muted">The easiest setup is from VRCX-0-Nanashi under Settings &gt; Sync Options. The app uses your saved VRChat session, so you do not need to copy cookies.</p>
      <details>
      <summary className="advanced-summary">Set up manually from this browser</summary>
      <p className="muted">This sends VRChat session cookies sealed to the server's collector. The server operator can use them to read your account activity. The collector is read-only and keeps the session until it expires, you lock it, or the collector stops.</p>
      <label>Vault<select value={selected} onChange={event => setSelected(event.target.value)}>{rows.map(({ vault }) => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId}</option>)}</select></label>
      <label>VRChat user ID<input autoComplete="off" value={vrchatUserId} onChange={event => setVrchatUserId(event.target.value)} placeholder={chosen ? 'Read from the vault manifest when possible' : 'usr_…'}/></label>
      <label>VRChat auth cookie<input type="password" autoComplete="off" value={authCookie} onChange={event => setAuthCookie(event.target.value)}/></label>
      <label>Two-factor auth cookie (optional)<input type="password" autoComplete="off" value={twoFactorCookie} onChange={event => setTwoFactorCookie(event.target.value)}/></label>
      <div className="form-grid"><label>Session duration (days)<input type="number" min="1" max="30" value={days} disabled={forever} onChange={event => setDays(event.target.value)}/></label><label className="check-label"><input type="checkbox" checked={forever} onChange={event => setForever(event.target.checked)}/><span>Run forever (no expiration)</span></label><label>Sync interval (seconds)<input type="number" min="60" max="900" value={interval} onChange={event => setInterval(event.target.value)}/></label></div>
      <button className="primary" disabled={!selected || !unlocked || !capabilities?.available} onClick={() => chosen && void start(chosen)}>Start collector</button>{!unlocked && <p className="muted"><a href="/dashboard/security">Unlock your sync key under Security</a> to seal and start a session.</p>}
      </details>
    </article>
  </>
}

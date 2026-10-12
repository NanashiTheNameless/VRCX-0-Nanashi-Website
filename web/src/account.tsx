import React, { useEffect, useState } from 'react'
import { apiFetch, failure, request } from './api'
import { createPassphraseEnvelope, normalizeSyncKey } from './envelopes'
import { useReauth } from './reauth'
import { formatBytes } from './site'
import { manifestInfo, manifestRetention, transferCode, transferParse, transferReceive, transferSend, transferStart, type ManifestInfo } from './protocol'

type Act = (work: () => Promise<void>) => Promise<void>
type Location = { city: string | null; region: string | null; country: string | null }
type IpEntry = { ip: string; location: Location; firstSeenMs: number; lastSeenMs: number }
type Client = {
  clientId: string
  kind: 'desktop' | 'web-session' | 'manual-token'
  label: string
  clientVersion: string | null
  scopes: string[]
  current: boolean
  activeNow: boolean
  revokedAtMs: number | null
  firstSeenMs: number | null
  lastSeenMs: number | null
  currentIp: IpEntry | null
  history: IpEntry[]
}
type Vault = { vaultId: string; createdAtMs: number; maxSeq: number; usageBytes: number }
type World = { world_id: string; name: string; author_name: string; image_url: string; description: string; comment: string }
type Collection = {
  id: string
  title: string
  note: string | null
  author_name: string
  author_profile: string | null
  category: string | null
  listed: boolean
  updated_at: number
  worlds: World[]
}

const KINDS = { desktop: 'VRCX-0-Nanashi', 'web-session': 'Website session', 'manual-token': 'Manual token' }
const SCOPES = [
  ['sync', 'Read and write encrypted history'],
  ['collector', 'Control the collector'],
  ['share', 'Manage shared collections'],
  ['account', 'Create and delete vaults, delete synced data'],
] as const
const WORLD_ID = /^wrld_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MAX_WORLDS = 500
const IMAGE_HOSTS = ['api.vrchat.cloud', 'assets.vrchat.com']
const REFUSE_BELOW_LOG10 = 50 * Math.log10(2)
const WARN_BELOW_LOG10 = 80 * Math.log10(2)

const when = (value: number | null) => (value ? new Date(value).toLocaleString() : 'Never')
const place = (location: Location) => [location.city, location.region, location.country].filter(Boolean).join(', ') || 'Unknown location'

export function TotpSetup({ secret, uri, children }: { secret: string; uri: string; children?: React.ReactNode }) {
  return (
    <div className="secret-box">
      <b>Authenticator setup key</b>
      <code className="secret-code">{secret}</code>
      {uri.startsWith('otpauth://') && <p><a href={uri}>Open in an authenticator app on this device</a></p>}
      <small>Add this key to your authenticator app, then enter the 6-digit code it shows.</small>
      {children}
    </div>
  )
}

export function AccountSecurity({ email, twofaMethod, act, onUpdated }: {
  email: string
  twofaMethod: string | null
  act: Act
  onUpdated: () => Promise<void>
}) {
  const reauth = useReauth(twofaMethod)
  const [newPassword, setNewPassword] = useState('')
  const [passwordChanged, setPasswordChanged] = useState(false)
  const [confirmPassword, setConfirmPassword] = useState('')
  const [totpSetup, setTotpSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [targetCode, setTargetCode] = useState('')
  const [emailChangeSent, setEmailChangeSent] = useState(false)

  return <>
    <section className="card wide">
      <h2>Verify it's you</h2>
      <p className="muted">Enter a verification code once to unlock changes on this page. It stays valid for a few minutes.</p>
      {reauth.fields}
    </section>
    <section className="card wide">
      <h2>Password</h2>
      <p className="muted">Change your password after verifying your current account security method. Other website sessions will be ended.</p>
      <label>New password<input type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={event => { setNewPassword(event.target.value); setPasswordChanged(false) }} /></label>
      <label>Confirm new password<input type="password" autoComplete="new-password" minLength={12} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} /></label>
      <button className="primary" disabled={!reauth.ready || newPassword.length < 12 || newPassword !== confirmPassword} onClick={() => act(async () => {
        if (newPassword !== confirmPassword) throw new Error('The passwords do not match.')
        await reauth.confirm()
        await request('/password', { method: 'PUT', body: JSON.stringify({ password: newPassword }) })
        setNewPassword(''); setConfirmPassword(''); setPasswordChanged(true); await onUpdated()
      })}>Change password</button>
      {newPassword && newPassword.length < 12 && <small>Use at least 12 characters.</small>}
      {confirmPassword && newPassword !== confirmPassword && <small>The passwords do not match.</small>}
      {passwordChanged && <div className="alert">Password changed.</div>}
    </section>
    <section className="card wide">
      <h2>Two-factor method</h2>
      <p className="muted">Current method: {twofaMethod === 'totp' ? 'Authenticator app' : twofaMethod === 'email' ? 'Email code' : 'Not set'}. Verify your current method before switching.</p>
      {twofaMethod !== 'totp' && !totpSetup && <button disabled={!reauth.ready} onClick={() => act(async () => {
        await reauth.confirm()
        setTotpSetup(await request('/security/twofa/totp', { method: 'POST' }))
      })}>Set up authenticator app</button>}
      {totpSetup && <TotpSetup secret={totpSetup.secret} uri={totpSetup.uri}><label>New authenticator code<input type="text" name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" value={targetCode} onChange={event => setTargetCode(event.target.value)} /></label><button className="primary" disabled={!targetCode} onClick={() => act(async () => {
        await request('/security/twofa/totp/confirm', { method: 'POST', body: JSON.stringify({ code: targetCode }) })
        setTotpSetup(null); setTargetCode(''); await onUpdated()
      })}>Confirm authenticator app</button></TotpSetup>}
      {twofaMethod !== 'email' && !emailChangeSent && <button disabled={!reauth.ready} onClick={() => act(async () => {
        await reauth.confirm()
        await request('/security/twofa/email', { method: 'POST' })
        setEmailChangeSent(true)
      })}>Use email codes instead</button>}
      {twofaMethod !== 'email' && emailChangeSent && <div className="secret-box"><p>A confirmation code was sent to {email}.</p><label>Email code<input type="text" name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]*" value={targetCode} onChange={event => setTargetCode(event.target.value)} /></label><button className="primary" disabled={!targetCode} onClick={() => act(async () => {
        await request('/security/twofa/email/confirm', { method: 'POST', body: JSON.stringify({ code: targetCode }) })
        setEmailChangeSent(false); setTargetCode(''); await onUpdated()
      })}>Confirm email codes</button></div>}
    </section>
  </>
}

export function Clients({ act, twofaMethod }: { act: Act; twofaMethod: string | null }) {
  const [clients, setClients] = useState<Client[]>([])
  const [open, setOpen] = useState<string | null>(null)
  const reauth = useReauth(twofaMethod)
  const refresh = async () => setClients(await request<Client[]>('/account/clients?history=true'))
  useEffect(() => { refresh().catch(() => setClients([])) }, [])
  const guarded = (work: () => Promise<unknown>) => act(async () => { await reauth.confirm(); await work(); await refresh() })

  return (
    <section className="card wide">
      <div className="section-heading">
        <div>
          <h2>Connected clients</h2>
          <p className="muted">Every app, browser session, and token that has used your account. Only you can see this list. IP history is kept for 90 days.</p>
        </div>
        <button onClick={() => act(refresh)}>Refresh</button>
      </div>
      {clients.length === 0 ? <div className="empty-state">No client records to show.</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Client</th><th>Kind</th><th>Status</th><th>Address</th><th /></tr></thead>
            <tbody>
              {clients.map(client => (
                <tr key={client.clientId}>
                  <td>
                    {client.label || client.clientId}{client.current && ' (this device)'}
                    {client.clientVersion && <small>{client.clientVersion}</small>}
                    {client.scopes.length > 0 && <small>{client.scopes.join(', ')}</small>}
                  </td>
                  <td>{KINDS[client.kind] ?? client.kind}</td>
                  <td>{client.revokedAtMs ? `Revoked ${when(client.revokedAtMs)}` : client.activeNow ? 'Active now' : `Last seen ${when(client.lastSeenMs)}`}</td>
                  <td>
                    {client.currentIp ? <>{client.currentIp.ip}<small>{place(client.currentIp.location)}</small></> : 'Unknown'}
                    {client.history.length > 0 && (
                      <button className="link" onClick={() => setOpen(open === client.clientId ? null : client.clientId)}>
                        {open === client.clientId ? 'Hide history' : `History (${client.history.length})`}
                      </button>
                    )}
                    {open === client.clientId && client.history.map(entry => (
                      <small key={`${entry.ip}-${entry.firstSeenMs}`}>{entry.ip}, {place(entry.location)}, {when(entry.firstSeenMs)} to {when(entry.lastSeenMs)}</small>
                    ))}
                  </td>
                  <td>
                    {!client.revokedAtMs && !client.current && (
                      <button disabled={!reauth.ready} onClick={() => guarded(() => request(`/account/clients/${client.clientId}/revoke`, { method: 'POST' }))}>Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted">Revoking another client or clearing history needs a fresh verification code. Revoking does not remove your encryption key from that device.</p>
      {reauth.fields}
      <div className="button-row">
        <button className="danger" disabled={!reauth.ready} onClick={() => guarded(() => request('/account/clients/revoke-others', { method: 'POST' }))}>Revoke all other clients</button>
        <button disabled={!reauth.ready} onClick={() => guarded(() => request('/account/clients/history', { method: 'DELETE' }))}>Clear IP history</button>
      </div>
    </section>
  )
}

export function Tokens({ act, twofaMethod }: { act: Act; twofaMethod: string | null }) {
  const [label, setLabel] = useState('')
  const [scopes, setScopes] = useState<string[]>(['sync'])
  const [token, setToken] = useState('')
  const reauth = useReauth(twofaMethod)
  const toggle = (scope: string) => setScopes(scopes.includes(scope) ? scopes.filter(item => item !== scope) : [...scopes, scope])

  return (
    <section className="card wide">
      <h2>Create a token</h2>
      <p className="muted">For setups that cannot use pairing. The token is shown once. Anyone who has it can act with the scopes you tick, so prefer pairing when you can.</p>
      <label>Label<input maxLength={64} value={label} onChange={event => setLabel(event.target.value)} /></label>
      {SCOPES.map(([scope, text]) => (
        <label className="check-label" key={scope}>
          <input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggle(scope)} />{scope}: {text}
        </label>
      ))}
      {reauth.fields}
      <button
        className="primary"
        disabled={!reauth.ready || !label.trim() || scopes.length === 0}
        onClick={() => act(async () => {
          await reauth.confirm()
          const created = await request<{ token: string }>('/tokens', { method: 'POST', body: JSON.stringify({ label, scopes }) })
          setToken(created.token)
          setLabel('')
        })}
      >
        Create token
      </button>
      {token && (
        <div className="secret-box">
          <b>Your new token</b>
          <code className="secret-code">{token}</code>
          <small>Copy it now. It cannot be shown again.</small>
          <div className="button-row">
            <button onClick={() => void navigator.clipboard.writeText(token)}>Copy</button>
            <button onClick={() => setToken('')}>I saved it</button>
          </div>
        </div>
      )}
    </section>
  )
}

const toBase64Url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const fromBase64Url = (text: string) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0))

function VaultSettings({ act, vaultId, hasLimit }: { act: Act; vaultId: string; hasLimit: boolean }) {
  const [state, setState] = useState<{ seq: number; blob: string; info: ManifestInfo } | null>(null)
  const [days, setDays] = useState('')
  const [margin, setMargin] = useState('')
  const [saved, setSaved] = useState(false)
  const path = `/vaults/${encodeURIComponent(vaultId)}/manifest`
  const load = async () => {
    const response = await apiFetch(path)
    if (!response.ok) throw await failure(response)
    const seq = Number(response.headers.get('x-manifest-seq'))
    const blob = toBase64Url(new Uint8Array(await response.arrayBuffer()))
    const info = await manifestInfo({ vaultId, manifestSeq: seq, manifest: blob })
    setState({ seq, blob, info })
    setDays(info.retention.maxAgeDays?.toString() ?? '')
    setMargin(info.retention.keepBelowLimitMarginPct?.toString() ?? '')
  }
  const number = (text: string, low: number, high: number) => {
    if (!text.trim()) return null
    const value = Number(text)
    if (!Number.isInteger(value) || value < low || value > high) throw new Error(`Enter a whole number from ${low} to ${high}, or leave it empty.`)
    return value
  }
  const save = () => act(async () => {
    const next = await manifestRetention({ vaultId, manifestSeq: state!.seq, manifest: state!.blob, maxAgeDays: number(days, 1, 3650), keepBelowLimitMarginPct: hasLimit ? number(margin, 1, 90) : null })
    const response = await apiFetch(path, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-manifest-seq': String(next.manifestSeq), 'if-match-seq': String(state!.seq) }, body: fromBase64Url(next.manifest) })
    if (!response.ok) throw await failure(response)
    await load()
    setSaved(true)
  })

  if (!state) return <button onClick={() => act(load)}>Show details</button>
  return (
    <div className="world-edit">
      <b>{state.info.subject ? `${state.info.subject.displayName} (${state.info.subject.vrchatUserId})` : 'Unnamed vault'}</b>
      <small>Devices allowed to write: {state.info.signers.map(signer => `${signer.label} (${signer.kind})`).join(', ') || 'none'}</small>
      <p className="muted">Retention removes old history from the server only. Your PCs keep everything, and a PC you add later receives only what is left. Your app applies these settings after its next sync. Memos, notes, and favorites are always kept.</p>
      <label>Keep only the last N days (1 to 3650, empty for no limit)<input inputMode="numeric" value={days} onChange={event => { setDays(event.target.value); setSaved(false) }} /></label>
      {hasLimit && <label>Stay this many percent below the storage limit (1 to 90, empty for off)<input inputMode="numeric" value={margin} onChange={event => { setMargin(event.target.value); setSaved(false) }} /></label>}
      <button className="primary" onClick={save}>Save retention</button>
      {saved && <small>Saved.</small>}
    </div>
  )
}

export function YourData({ act, usageBytes, quotaBytes, email, twofaMethod, unlocked, onDeleted }: { act: Act; usageBytes: number; quotaBytes: number | null; email: string; twofaMethod: string | null; unlocked: boolean; onDeleted: () => void }) {
  const [vaults, setVaults] = useState<Vault[]>([])
  const [typed, setTyped] = useState('')
  const [keepCollections, setKeepCollections] = useState(true)
  const reauth = useReauth(twofaMethod)
  const refresh = async () => setVaults(await request<Vault[]>('/vaults'))
  useEffect(() => { refresh().catch(() => setVaults([])) }, [])
  const used = quotaBytes ? Math.min(100, usageBytes / quotaBytes * 100) : 0
  const confirmed = typed.trim().toLowerCase() === email.toLowerCase()

  return (
    <>
      <section className="card wide">
        <h2>Usage</h2>
        <strong>{formatBytes(usageBytes)}</strong>
        <div className="progress"><i style={{ width: `${used}%` }} /></div>
        <small>{quotaBytes ? `of ${formatBytes(quotaBytes)} limit` : 'No storage limit'}</small>
        {used >= 95 ? <div className="alert error">Your storage is almost full. New uploads are refused at the limit.</div> : used >= 80 && <div className="alert">You have used more than 80% of your storage.</div>}
      </section>
      <section className="card wide">
        <div className="section-heading">
          <div>
            <h2>Vaults</h2>
            <p className="muted">One vault per VRChat account you sync. The server cannot tell which VRChat account a vault belongs to, so vaults are listed by id and date. Unlock your key under Security to see which account each vault holds and to set retention.</p>
          </div>
          <button onClick={() => act(refresh)}>Refresh</button>
        </div>
        {vaults.length === 0 ? <div className="empty-state">No synced data is stored for this account.</div> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Vault</th><th>Created</th><th>Chunks</th><th>Size</th><th /></tr></thead>
              <tbody>
                {vaults.map(vault => (
                  <tr key={vault.vaultId}>
                    <td>{vault.vaultId}{unlocked && <VaultSettings act={act} vaultId={vault.vaultId} hasLimit={quotaBytes !== null} />}</td>
                    <td>{when(vault.createdAtMs)}</td>
                    <td>{vault.maxSeq}</td>
                    <td>{formatBytes(vault.usageBytes)}</td>
                    <td>
                      <button className="danger" disabled={!reauth.ready} onClick={() => { if (confirm(`Delete vault ${vault.vaultId} from the server? History on your PCs is not touched.`)) void act(async () => { await reauth.confirm(); await request(`/vaults/${encodeURIComponent(vault.vaultId)}`, { method: 'DELETE' }); await refresh() }) }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="card wide">
        <h2>Delete</h2>
        <p className="muted">Deletion happens immediately and cannot be undone. History on your PCs is not touched; a PC that still has it uploads it again the next time it syncs.</p>
        {reauth.fields}
        <label>Type your account email to confirm<input autoComplete="off" value={typed} onChange={event => setTyped(event.target.value)} /></label>
        <label className="check-label"><input type="checkbox" checked={keepCollections} onChange={event => setKeepCollections(event.target.checked)} />Keep my shared world collections</label>
        <div className="button-row">
          <button
            className="danger"
            disabled={!reauth.ready || !confirmed}
            onClick={() => { if (confirm('Delete all synced data from the server now? This cannot be undone.')) void act(async () => { await reauth.confirm(); await request(`/account/data${keepCollections ? '?keepCollections=true' : ''}`, { method: 'DELETE' }); setTyped(''); await refresh() }) }}
          >
            Delete all synced data
          </button>
          <button
            className="danger"
            disabled={!reauth.ready || !confirmed}
            onClick={() => { if (confirm('Permanently delete this account and everything stored for it?')) void act(async () => { await reauth.confirm(); await request('/account', { method: 'DELETE' }); onDeleted() }) }}
          >
            Delete account
          </button>
        </div>
        <small>Deleting synced data removes every vault and stored key envelope and destroys this account's server-side key. Deleting the account also removes your sign-in, tokens, and collections.</small>
      </section>
    </>
  )
}

export function KeyUnlock({ act, unlocked, onUnlock, onForget }: { act: Act; unlocked: boolean; onUnlock: (key: string) => Promise<void>; onForget: () => Promise<void> }) {
  const [input, setInput] = useState('')
  return (
    <article className="card">
      <h2>Unlock with your key</h2>
      <p className="muted">Paste your recovery string or 64-character key to read your history in this tab. It stays in this browser tab and is never sent to the server.</p>
      {unlocked ? <button onClick={() => act(onForget)}>Forget key in this tab</button> : (
        <>
          <label>Recovery string or key<input type="password" autoComplete="off" value={input} onChange={event => setInput(event.target.value)} /></label>
          <button className="primary" disabled={!input.trim()} onClick={() => act(async () => { await onUnlock(normalizeSyncKey(input)); setInput('') })}>Unlock</button>
        </>
      )}
    </article>
  )
}

export function DeviceTransfer({ act, accountId, unlocked, twofaMethod, onReceived }: { act: Act; accountId: string; unlocked: boolean; twofaMethod: string | null; onReceived: () => void }) {
  const [incoming, setIncoming] = useState<{ transferId: string; code: string } | null>(null)
  const [code, setCode] = useState('')
  const [sent, setSent] = useState(false)
  const reauth = useReauth(twofaMethod)

  useEffect(() => {
    if (!incoming) return
    let stopped = false
    const started = Date.now()
    const poll = async () => {
      if (stopped) return
      if (Date.now() - started > 10 * 60 * 1000) return setIncoming(null)
      const response = await apiFetch(`/transfer/${incoming.transferId}/result`).catch(() => null)
      if (stopped) return
      if (response?.ok) {
        const blob = toBase64Url(new Uint8Array(await response.arrayBuffer()))
        await act(async () => { await transferReceive({ accountId, transferId: incoming.transferId, blob }); onReceived() })
        return setIncoming(null)
      }
      if (response && response.status !== 400) return setIncoming(null)
      setTimeout(poll, 3000)
    }
    void poll()
    return () => { stopped = true }
  }, [incoming])

  const receive = () => act(async () => {
    const { epk } = await transferStart()
    const created = await request<{ transferId: string }>('/transfer', { method: 'POST', body: JSON.stringify({ epk }) })
    setIncoming({ transferId: created.transferId, code: (await transferCode(created.transferId)).code })
  })
  const send = () => act(async () => {
    const { transferId } = await transferParse(code)
    const { epk } = await request<{ epk: string }>(`/transfer/${transferId}`)
    const { blob } = await transferSend({ accountId, code, epk })
    await reauth.confirm()
    const response = await apiFetch(`/transfer/${transferId}`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream' }, body: fromBase64Url(blob) })
    if (!response.ok) throw await failure(response)
    setCode('')
    setSent(true)
  })

  return (
    <article className="card">
      <h2>Move your key between devices</h2>
      <p className="muted">The key is encrypted on the sending device for the receiving one. The server passes it along and cannot read it. Both devices must be signed in to this account.</p>
      {unlocked ? (
        <>
          <label>Code shown on the new device<input autoComplete="off" value={code} onChange={event => { setCode(event.target.value); setSent(false) }} /></label>
          {reauth.note}
          <button className="primary" disabled={!code.trim() || !reauth.ready} onClick={send}>Send key to that device</button>
          {sent && <div className="alert">Sent. The other device unlocks within a few seconds.</div>}
        </>
      ) : incoming ? (
        <div className="secret-box">
          <b>Enter this code on a device that has your key</b>
          <pre>{incoming.code}</pre>
          <small>Waiting for the other device. The code expires after 10 minutes.</small>
          <button onClick={() => setIncoming(null)}>Cancel</button>
        </div>
      ) : (
        <button onClick={receive}>Receive my key on this browser</button>
      )}
    </article>
  )
}

const emptyCollection = (): Collection => ({ id: '', title: '', note: '', author_name: '', author_profile: '', category: '', listed: false, updated_at: 0, worlds: [] })

function vrchatImage(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && IMAGE_HOSTS.includes(url.hostname)
  } catch {
    return false
  }
}

function worldIdFrom(input: string) {
  const match = input.match(/wrld_[0-9a-f-]{36}/i)
  return match && WORLD_ID.test(match[0]) ? match[0] : null
}

export function Collections({ act }: { act: Act }) {
  const [items, setItems] = useState<Collection[]>([])
  const [draft, setDraft] = useState<Collection | null>(null)
  const [worldInput, setWorldInput] = useState('')
  const [copied, setCopied] = useState('')
  const refresh = async () => setItems(await request<Collection[]>('/collections'))
  useEffect(() => { refresh().catch(() => setItems([])) }, [])
  const set = (patch: Partial<Collection>) => setDraft(current => current && { ...current, ...patch })
  const setWorld = (index: number, patch: Partial<World>) => set({ worlds: draft!.worlds.map((world, at) => at === index ? { ...world, ...patch } : world) })
  const move = (index: number, by: number) => {
    const worlds = [...draft!.worlds]
    const target = index + by
    if (target < 0 || target >= worlds.length) return
    ;[worlds[index], worlds[target]] = [worlds[target], worlds[index]]
    set({ worlds })
  }
  const addWorld = () => {
    const id = worldIdFrom(worldInput)
    if (!id || draft!.worlds.some(world => world.world_id === id) || draft!.worlds.length >= MAX_WORLDS) return
    set({ worlds: [...draft!.worlds, { world_id: id, name: '', author_name: '', image_url: '', description: '', comment: '' }] })
    setWorldInput('')
  }
  const save = () => act(async () => {
    const badImage = draft!.worlds.find(world => world.image_url && !vrchatImage(world.image_url))
    if (badImage) throw new Error(`The image link for ${badImage.name || badImage.world_id} must be an https link on api.vrchat.cloud or assets.vrchat.com.`)
    const body = JSON.stringify({ ...draft, note: draft!.note || null, author_profile: draft!.author_profile || null, category: draft!.category || null })
    await request(draft!.id ? `/collections/${draft!.id}` : '/collections', { method: draft!.id ? 'PUT' : 'POST', body })
    setDraft(null)
    await refresh()
  })

  if (draft) {
    return (
      <section className="card wide">
        <h2>{draft.id ? 'Edit collection' : 'New collection'}</h2>
        <p className="muted">Shared collections are public: anyone with the link can read everything you enter here.</p>
        <label>Title<input maxLength={120} value={draft.title} onChange={event => set({ title: event.target.value })} /></label>
        <label>Your name as shown<input maxLength={80} value={draft.author_name} onChange={event => set({ author_name: event.target.value })} /></label>
        <label>Profile link (optional)<input type="url" value={draft.author_profile ?? ''} onChange={event => set({ author_profile: event.target.value })} /></label>
        <label>Category (optional)<input maxLength={40} value={draft.category ?? ''} onChange={event => set({ category: event.target.value })} /></label>
        <label>Note (optional)<input maxLength={500} value={draft.note ?? ''} onChange={event => set({ note: event.target.value })} /></label>
        <label className="check-label"><input type="checkbox" checked={draft.listed} onChange={event => set({ listed: event.target.checked })} />List in the public directory</label>
        <h2>Worlds ({draft.worlds.length} of {MAX_WORLDS})</h2>
        <div className="button-row">
          <input placeholder="World id or VRChat world link" value={worldInput} onChange={event => setWorldInput(event.target.value)} />
          <button disabled={!worldIdFrom(worldInput)} onClick={addWorld}>Add world</button>
        </div>
        {draft.worlds.map((world, index) => (
          <div className="world-edit" key={world.world_id}>
            <div className="eyebrow">{world.world_id}</div>
            <label>Name<input maxLength={200} value={world.name} onChange={event => setWorld(index, { name: event.target.value })} /></label>
            <label>Author<input maxLength={200} value={world.author_name} onChange={event => setWorld(index, { author_name: event.target.value })} /></label>
            <label>Description<input maxLength={500} value={world.description} onChange={event => setWorld(index, { description: event.target.value })} /></label>
            <label>Image link (VRChat image hosts only)<input type="url" value={world.image_url} onChange={event => setWorld(index, { image_url: event.target.value })} /></label>
            <label>Comment<input maxLength={500} value={world.comment} onChange={event => setWorld(index, { comment: event.target.value })} /></label>
            <div className="button-row">
              <button disabled={index === 0} onClick={() => move(index, -1)}>Move up</button>
              <button disabled={index === draft.worlds.length - 1} onClick={() => move(index, 1)}>Move down</button>
              <button className="danger" onClick={() => set({ worlds: draft.worlds.filter((_, at) => at !== index) })}>Remove</button>
            </div>
          </div>
        ))}
        <div className="button-row">
          <button className="primary" disabled={!draft.title.trim() || !draft.author_name.trim()} onClick={save}>Save</button>
          <button onClick={() => setDraft(null)}>Cancel</button>
        </div>
      </section>
    )
  }

  return (
    <section className="card wide">
      <div className="section-heading">
        <div>
          <h2>Shared world collections</h2>
          <p className="muted">Public lists of worlds that anyone with the link can open and import into VRCX-0-Nanashi.</p>
        </div>
        <button className="primary" onClick={() => setDraft(emptyCollection())}>New collection</button>
      </div>
      {items.length === 0 ? <div className="empty-state">You have not shared any collections.</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Title</th><th>Worlds</th><th>Listed</th><th>Updated</th><th /></tr></thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id}>
                  <td><a href={`/c/${item.id}`}>{item.title}</a></td>
                  <td>{item.worlds.length}</td>
                  <td>{item.listed ? 'Yes' : 'No'}</td>
                  <td>{when(item.updated_at * 1000)}</td>
                  <td>
                    <div className="button-row">
                      <button onClick={() => setDraft(item)}>Edit</button>
                      <button onClick={() => void navigator.clipboard.writeText(`${location.origin}/c/${item.id}`).then(() => setCopied(item.id))}>{copied === item.id ? 'Link copied' : 'Copy link'}</button>
                      <button className="danger" onClick={() => { if (confirm(`Delete the collection "${item.title}"? Its link stops working.`)) void act(async () => { await request(`/collections/${item.id}`, { method: 'DELETE' }); await refresh() }) }}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join('\n')
  const download = () => {
    const link = document.createElement('a')
    link.href = URL.createObjectURL(new Blob([`RemoteSync recovery codes\n\n${text}\n`], { type: 'text/plain' }))
    link.download = 'remotesync-recovery-codes.txt'
    link.click()
    URL.revokeObjectURL(link.href)
  }
  return (
    <section className="card wide">
      <h2>Save your recovery codes</h2>
      <p className="muted">Each code works once in place of your authenticator or email code. They are shown only this one time and cannot be shown again.</p>
      <pre className="recovery-codes">{text}</pre>
      <div className="button-row">
        <button onClick={() => void navigator.clipboard.writeText(text)}>Copy</button>
        <button onClick={download}>Download</button>
        <button onClick={() => window.print()}>Print</button>
        <button className="primary" onClick={onDone}>I saved these codes</button>
      </div>
    </section>
  )
}

export function ChosenPassphrase({ act, accountId, twofaMethod, onSaved }: { act: Act; accountId: string; twofaMethod: string | null; onSaved: () => void }) {
  const [syncKey, setSyncKey] = useState('')
  const [label, setLabel] = useState('My passphrase')
  const [passphrase, setPassphrase] = useState('')
  const [repeat, setRepeat] = useState('')
  const [strength, setStrength] = useState<number | null>(null)
  const [accepted, setAccepted] = useState(false)
  const reauth = useReauth(twofaMethod)

  useEffect(() => {
    let current = true
    setAccepted(false)
    if (!passphrase) return setStrength(null)
    void import('zxcvbn').then(module => { if (current) setStrength(module.default(passphrase.slice(0, 128)).guesses_log10) })
    return () => { current = false }
  }, [passphrase])

  const refused = strength !== null && strength < REFUSE_BELOW_LOG10
  const weak = strength !== null && !refused && strength < WARN_BELOW_LOG10
  const ready = strength !== null && !refused && (!weak || accepted) && passphrase === repeat && syncKey.trim() && label.trim() && reauth.ready

  return (
    <article className="card">
      <h2>Envelope with your own passphrase</h2>
      <p className="muted">Stores an encrypted copy of your key on the server, locked with a passphrase you choose. Whoever runs the server could try to guess that passphrase offline, so only its strength protects your history. A passkey or generated passphrase does not have this weakness.</p>
      <label>Sync key (64 hex characters or rss1 recovery string)<input type="password" autoComplete="off" value={syncKey} onChange={event => setSyncKey(event.target.value)} /></label>
      <label>Envelope label<input maxLength={64} value={label} onChange={event => setLabel(event.target.value)} /></label>
      <label>Passphrase<input type="password" autoComplete="new-password" value={passphrase} onChange={event => setPassphrase(event.target.value)} /></label>
      <label>Repeat passphrase<input type="password" autoComplete="new-password" value={repeat} onChange={event => setRepeat(event.target.value)} /></label>
      {refused && <div className="alert error">This passphrase is too easy to guess and cannot be used. Make it longer or less predictable.</div>}
      {weak && (
        <>
          <div className="alert">This passphrase could be guessed by someone with enough computing power and a copy of the envelope.</div>
          <label className="check-label"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)} />I understand and want to use it anyway</label>
        </>
      )}
      {passphrase && repeat && passphrase !== repeat && <div className="alert error">The two passphrases do not match.</div>}
      {reauth.note}
      <button
        className="primary"
        disabled={!ready}
        onClick={() => act(async () => {
          const envelope = await createPassphraseEnvelope(accountId, normalizeSyncKey(syncKey), label, passphrase, false)
          await reauth.confirm()
          await request('/envelopes', { method: 'POST', body: JSON.stringify(envelope) })
          setSyncKey('')
          setPassphrase('')
          setRepeat('')
          onSaved()
        })}
      >
        Encrypt and save envelope
      </button>
    </article>
  )
}

type PairInfo = { deviceLabel: string; userCode: string; expiresAtMs: number; requestedScopes: string[] }

export function Pairing({ act, twofaMethod }: { act: Act; twofaMethod: string | null }) {
  const [code, setCode] = useState('')
  const [info, setInfo] = useState<PairInfo | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const reauth = useReauth(twofaMethod)
  const path = `/pair/${encodeURIComponent(code.trim())}`
  const toggle = (scope: string) => setScopes(scopes.includes(scope) ? scopes.filter(item => item !== scope) : [...scopes, scope])

  return (
    <section className="card wide">
      <h2>Approve a device</h2>
      <p className="muted">Enter the code shown in VRCX-0-Nanashi. Check the device name, and untick any permission you do not want to give it.</p>
      <label>Device code<input autoComplete="off" autoCapitalize="characters" spellCheck={false} value={code} onChange={event => { setCode(event.target.value.toUpperCase()); setInfo(null) }} placeholder="ABCD-EFGH" /></label>
      {!info ? (
        <button className="primary" disabled={!code.trim()} onClick={() => act(async () => { const result = await request<PairInfo>(`/pair/${encodeURIComponent(code.trim())}`); setInfo(result); setScopes(result.requestedScopes) })}>Review device</button>
      ) : (
        <>
          <div className="pair-info">
            <b>{info.deviceLabel}</b>
            <span>Code: {info.userCode}</span>
            <span>Expires: {when(info.expiresAtMs)}</span>
          </div>
          {SCOPES.filter(([scope]) => info.requestedScopes.includes(scope)).map(([scope, text]) => (
            <label className="check-label" key={scope}><input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggle(scope)} />{scope}: {text}</label>
          ))}
          {reauth.fields}
          <div className="button-row">
            <button className="primary" disabled={!reauth.ready || scopes.length === 0} onClick={() => act(async () => { await reauth.confirm(); await request(`${path}/approve`, { method: 'POST', body: JSON.stringify({ scopes }) }); setInfo(null); setCode('') })}>Approve device</button>
            <button className="danger" onClick={() => act(async () => { await request(`${path}/deny`, { method: 'POST' }); setInfo(null) })}>Deny</button>
          </div>
        </>
      )}
    </section>
  )
}

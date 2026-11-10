import { useEffect, useState } from 'react'

import { apiOriginFetch } from './api'
import { followKeys, followOpen, type FollowLocation } from './protocol'
import { appLink, vrchatLink } from './relayLinks'
import { emojiLabel, parseFollowLink, parsePartyLink, partyAppLink, userAppLink, userVrchatLink, type FollowRequirement } from './followLinks'
import { SitePage } from './site'

const REQUIREMENT_TEXT: Record<FollowRequirement, string> = {
  friend: 'be their friend',
  verified: 'be age verified',
  adult: 'be age verified as 18+',
  group: 'be in one of their groups',
}

function NotRecognized() {
  return <SitePage title="Link not recognized">
    <article className="card"><h1>Link not recognized</h1><p className="muted">This follow or party link is incomplete or damaged.</p><a className="button" href="/">Back to home</a></article>
  </SitePage>
}

export function FollowPage() {
  const link = parseFollowLink(location.hash)
  if (!link) return <NotRecognized/>
  const who = link.name || 'This person'
  return <SitePage title={`Follow ${who}`}>
    <article className="card relay">
      <div className="eyebrow">FOLLOW LINK</div>
      <h1>Join {who}</h1>
      <p>Send {who} a request invite in VRChat. Their VRCX-0-Nanashi checks your request and invites you if you qualify. This page never shows where they are.</p>
      {link.requirements.length > 0 && <p className="muted">To be invited you need to {link.requirements.map(requirement => REQUIREMENT_TEXT[requirement]).join(', or ')}.</p>}
      {link.emoji && <p className="muted">Want an invite every time they move? Boop them with <strong>{emojiLabel(link.emoji)}</strong>. Boop them with <strong>Stop</strong> to cancel.</p>}
      <small>Shared by the person who sent this link. It was not checked by this website, and their app makes the final decision.</small>
      <div className="relay-actions">
        <a className="button primary" href={userAppLink(link.userId)}>Open in VRCX-0-Nanashi</a>
        <a className="button" href={userVrchatLink(link.userId)} rel="noreferrer">Open on the VRChat website</a>
      </div>
    </article>
  </SitePage>
}

export function PartyPage() {
  const party = parsePartyLink(location.hash)
  if (!party) return <NotRecognized/>
  const members = party.members.filter(member => member.role === 'member').length
  const guests = party.members.length - members
  return <SitePage title={party.name || 'Party'}>
    <article className="card relay">
      <div className="eyebrow">PARTY</div>
      <h1>{party.name || 'Party invitation'}</h1>
      <p>{members} {members === 1 ? 'member' : 'members'}{guests > 0 ? ` and ${guests} ${guests === 1 ? 'guest' : 'guests'}` : ''}. {party.followMode === 'leader' ? 'Everyone follows the leader.' : 'Everyone follows whoever moves.'}</p>
      <p className="muted">With VRCX-0-Nanashi: open the party in the app and confirm. Then boop the members with <strong>{emojiLabel(party.emoji)}</strong> so they know you are in. As a guest without the app, send a member a request invite, or boop them with <strong>{emojiLabel(party.emoji)}</strong> to get invites when they move. Boop <strong>Stop</strong> to cancel.</p>
      <small>Shared by the person who sent this link. It was not checked by this website.</small>
      <div className="relay-actions">
        <a className="button primary" href={partyAppLink(party)}>Open in VRCX-0-Nanashi</a>
      </div>
    </article>
  </SitePage>
}

const FOLLOW_REFRESH_MS = 15_000
const STALE_SECONDS = 10 * 60

type ShareView = { updatedAt: number | null; expiresAt: number; password?: unknown; sealed?: string | null }

async function followApi<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiOriginFetch(`/public/v2/follow/${path}`, init)
  if (response.status === 403) throw new Error('Wrong password.')
  if (response.status === 404) throw new Error('This follow link is not active anymore.')
  if (response.status === 429) throw new Error('Too many tries. Wait a minute and try again.')
  if (!response.ok) throw new Error(`Could not load the location (${response.status}).`)
  return await response.json() as T
}

export function FollowSharePage({ code }: { code: string }) {
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ''))
  const linkKey = fragment.get('k') ?? ''
  const sharer = Array.from((fragment.get('n') ?? '').trim()).slice(0, 60).join('')
  const valid = /^[A-Za-z0-9]{10}$/.test(code) && /^[A-Za-z0-9_-]{43}$/.test(linkKey)
  const [view, setView] = useState<ShareView | null>(null)
  const [keys, setKeys] = useState<{ contentKey: string; auth: string | null } | null>(null)
  const [password, setPassword] = useState('')
  const [unlocking, setUnlocking] = useState(false)
  const [current, setCurrent] = useState<FollowLocation | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!valid) return
    let active = true
    const refresh = async () => {
      try {
        const next = await followApi<ShareView>(code)
        if (!active) return
        setView(next)
        let derived = keys
        if (!derived && !next.password) {
          derived = await followKeys({ linkKey })
          if (active) setKeys(derived)
        }
        if (!derived) return
        const sealed = next.password
          ? (await followApi<{ sealed: string }>(`${code}/open`, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ auth: derived.auth }),
            })).sealed
          : next.sealed
        if (!sealed) { if (active) setCurrent(null); return }
        const opened = await followOpen({ contentKey: derived.contentKey, code, sealed })
        if (active) { setCurrent(opened); setError('') }
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : String(cause))
      }
    }
    void refresh()
    const timer = window.setInterval(() => { void refresh() }, FOLLOW_REFRESH_MS)
    return () => { active = false; window.clearInterval(timer) }
  }, [code, linkKey, valid, keys])

  if (!valid) return <NotRecognized/>
  const who = sharer || 'Someone'

  async function unlock(event: React.FormEvent) {
    event.preventDefault()
    if (!view?.password) return
    setUnlocking(true)
    setError('')
    try {
      setKeys(await followKeys({ linkKey, lock: view.password, password }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setUnlocking(false)
    }
  }

  const needsPassword = Boolean(view?.password) && !keys
  const state = current?.state
  const stale = current ? Date.now() / 1000 - current.updatedAt > STALE_SECONDS : false
  const target = state?.kind === 'instance'
    ? { kind: 'instance' as const, worldId: state.worldId, instanceId: state.instanceId, shortName: '', launchToken: '' }
    : null
  return <SitePage title={`Where ${who} is`}>
    <article className="card relay">
      <div className="eyebrow">LIVE LOCATION</div>
      <h1>{state?.kind === 'instance' ? state.worldName || state.worldId : `Where ${who} is`}</h1>
      {needsPassword && <form onSubmit={event => { void unlock(event) }}>
        <p>This link needs a password.</p>
        <input type="password" autoComplete="off" value={password} onChange={event => setPassword(event.target.value)} aria-label="Password" />
        <button className="button primary" type="submit" disabled={unlocking || password.length < 8}>{unlocking ? 'Unlocking...' : 'Unlock'}</button>
      </form>}
      {!needsPassword && !current && !error && <p className="muted">Waiting for {who} to share a location.</p>}
      {state?.kind === 'offline' && <p>{who} is offline.</p>}
      {state?.kind === 'private' && <p>{who} is in a private instance. Ask them for an invite.</p>}
      {target && <p className="relay-id">{target.worldId}:{target.instanceId}</p>}
      {stale && <p className="muted">Last updated over 10 minutes ago. Their PC may be off.</p>}
      {error && <p className="error">{error}</p>}
      <small>The location is encrypted with a key in this link; the website cannot read it. VRChat still decides who may join.</small>
      {target && <div className="relay-actions">
        <a className="button primary" href={vrchatLink(target)} rel="noreferrer">Join in VRChat</a>
        <a className="button" href={appLink(target)}>Open in VRCX-0-Nanashi</a>
      </div>}
    </article>
  </SitePage>
}

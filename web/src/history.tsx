import React, { useEffect, useMemo, useState } from 'react'
import { Activity, ChevronDown, Clock3 } from 'lucide-react'
import { request, requestBinary } from './api'
import { verifyAndOpenBatch, verifyAndOpenLive } from './protocol'
import { clearHistoryCache, readHistoryCache, writeHistoryCache } from './historyCache'

type VaultInfo = { vaultId: string; maxSeq: number; manifestSeq: number; usageBytes: number; createdAtMs: number }
type OpenChunk = { header: { chunkId: string; sourceSeq: number; kind: string; createdAtMs: number }; body: { streams: Record<string, unknown[]> } }
type HistoryView = 'all' | 'feed' | 'friends' | 'notifications' | 'moderation' | 'gamelog' | 'profile' | 'graph'

const historyViews: { id: HistoryView; label: string }[] = [
  { id: 'all', label: 'All activity' }, { id: 'feed', label: 'Status and presence' },
  { id: 'friends', label: 'Friend log' }, { id: 'notifications', label: 'Notifications' },
  { id: 'moderation', label: 'Moderation' }, { id: 'gamelog', label: 'Game log' },
  { id: 'profile', label: 'Profiles and saved data' }, { id: 'graph', label: 'Mutual friends data' },
]

function viewForStream(stream: string): HistoryView {
  if (stream.startsWith('feed_')) return 'feed'
  if (stream === 'friend_log_history') return 'friends'
  if (stream.startsWith('notifications')) return 'notifications'
  if (stream === 'moderation') return 'moderation'
  if (stream.startsWith('gamelog_')) return 'gamelog'
  if (stream.startsWith('mutual_graph')) return 'graph'
  return 'profile'
}

function encode64url(bytes: Uint8Array) {
  return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function decodeBatch(bytes: Uint8Array) {
  const frames: { seq: number; chunkId: string; blob: string }[] = []
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let offset = 0
  while (offset < bytes.length) {
    if (bytes.length - offset < 28) throw new Error('The server returned an incomplete chunk batch.')
    const seqBig = view.getBigUint64(offset, false)
    if (seqBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('This vault sequence is too large for this browser.')
    const seq = Number(seqBig)
    const chunkId = encode64url(bytes.subarray(offset + 8, offset + 24))
    const length = view.getUint32(offset + 24, false)
    offset += 28
    if (length > bytes.length - offset) throw new Error('The server returned a truncated chunk.')
    frames.push({ seq, chunkId, blob: encode64url(bytes.subarray(offset, offset + length)) })
    offset += length
  }
  return frames
}

export function HistoryBrowser({ unlocked, accountId }: { unlocked: boolean; accountId: string }) {
  const [vaults, setVaults] = useState<VaultInfo[]>([])
  const [vaultId, setVaultId] = useState('')
  const [manifest, setManifest] = useState<{ seq: number; blob: string } | null>(null)
  const [chunks, setChunks] = useState<OpenChunk[]>([])
  const [before, setBefore] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [query, setQuery] = useState('')
  const [streamFilter, setStreamFilter] = useState('')
  const [view, setView] = useState<HistoryView>('all')
  const [fromDate, setFromDate] = useState('')
  const [throughDate, setThroughDate] = useState('')
  const [detailEntity, setDetailEntity] = useState<{ id: string; kind: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let active = true
    setChunks([]); setManifest(null); setBefore(0); setHasMore(false); setError('')
    if (!unlocked) { setVaults([]); setVaultId(''); return }
    request<VaultInfo[]>('/vaults').then(async items => {
      if (!active) return
      setVaults(items)
      await writeHistoryCache(accountId, 'vaults', items)
      const selected = items.find(item => item.vaultId === vaultId) ?? items[0]
      setVaultId(selected?.vaultId ?? '')
      setBefore(selected ? selected.maxSeq + 1 : 0)
    }).catch(async e => {
      const cached = await readHistoryCache<VaultInfo[]>(accountId, 'vaults')
      if (!active) return
      if (cached) { setVaults(cached); const selected = cached.find(item => item.vaultId === vaultId) ?? cached[0]; setVaultId(selected?.vaultId ?? ''); setBefore(selected ? selected.maxSeq + 1 : 0) }
      else setError((e as Error).message)
    })
    return () => { active = false }
  }, [unlocked, accountId])

  const openNext = async () => {
    if (!vaultId || !unlocked) return
    setBusy(true); setError(''); setNotice('')
    try {
      let currentManifest = manifest
      if (!currentManifest) {
        try {
          const response = await requestBinary(`/vaults/${encodeURIComponent(vaultId)}/manifest`)
          const seq = Number(response.headers.get('x-manifest-seq'))
          if (!Number.isSafeInteger(seq) || seq < 1) throw new Error('The vault manifest sequence is invalid.')
          currentManifest = { seq, blob: encode64url(new Uint8Array(await response.arrayBuffer())) }
          await writeHistoryCache(accountId, `manifest:${vaultId}`, currentManifest)
        } catch (error) {
          currentManifest = await readHistoryCache<typeof currentManifest>(accountId, `manifest:${vaultId}`) ?? null
          if (!currentManifest) throw error
        }
        setManifest(currentManifest)
      }
      const query = `before=${before}&limit=50`
      let listing: { chunks: { seq: number; chunkId: string }[]; hasMore: boolean }
      try { listing = await request(`/vaults/${encodeURIComponent(vaultId)}/chunks?${query}`); await writeHistoryCache(accountId, `listing:${vaultId}:${before}`, listing) }
      catch (error) { const cached = await readHistoryCache<typeof listing>(accountId, `listing:${vaultId}:${before}`); if (!cached) throw error; listing = cached }
      if (!listing.chunks.length) { setHasMore(false); return }
      let batch: ArrayBuffer
      try { const response = await requestBinary(`/vaults/${encodeURIComponent(vaultId)}/chunks:batch?${query}`); batch = await response.arrayBuffer(); await writeHistoryCache(accountId, `batch:${vaultId}:${before}`, batch) }
      catch (error) { const cached = await readHistoryCache<ArrayBuffer>(accountId, `batch:${vaultId}:${before}`); if (!cached) throw error; batch = cached }
      const frames = decodeBatch(new Uint8Array(batch))
      if (!frames.length) throw new Error('The server returned no chunks for this vault page.')
      const rollbackKey = `remotesync.manifest-seq.${accountId}.${vaultId}`
      const savedSeq = Number(localStorage.getItem(rollbackKey) ?? 0)
      const highestManifestSeq = Number.isSafeInteger(savedSeq) && savedSeq > 0 ? savedSeq : null
      const opened = await verifyAndOpenBatch({ vaultId, manifestSeq: currentManifest.seq, highestManifestSeq, manifest: currentManifest.blob, chunks: frames.map(({ chunkId, blob }) => ({ chunkId, blob })) }) as OpenChunk[]
      localStorage.setItem(rollbackKey, String(Math.max(savedSeq || 0, currentManifest.seq)))
      setChunks(current => [...current, ...opened])
      setBefore(Math.min(...frames.map(frame => frame.seq)))
      setHasMore(listing.hasMore)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const streams = [...new Set(chunks.flatMap(chunk => Object.keys(chunk.body.streams)))].sort()
  const fromMs = fromDate ? localDateBoundary(fromDate) : null
  const untilMs = throughDate ? localDateBoundary(throughDate, true) : null
  const rows = useMemo(() => chunks.flatMap(chunk => Object.entries(chunk.body.streams).flatMap(([stream, values]) => values.map((value, index) => ({ chunk, stream, value, index, time: rowTime(value, chunk.header.createdAtMs) }))))
    .filter(row => view === 'all' || viewForStream(row.stream) === view)
    .filter(row => !streamFilter || row.stream === streamFilter)
    .filter(row => !query.trim() || `${row.stream} ${JSON.stringify(row.value)}`.toLowerCase().includes(query.trim().toLowerCase()))
    .filter(row => fromMs === null || row.time >= fromMs)
    .filter(row => untilMs === null || row.time < untilMs)
    .sort((a, b) => b.time - a.time), [chunks, query, streamFilter, view, fromMs, untilMs])

  const summaries = useMemo(() => {
    const counts = new Map<string, number>()
    const worldIds = new Set<string>()
    const friendIds = new Set<string>()
    for (const chunk of chunks) for (const [stream, values] of Object.entries(chunk.body.streams)) {
      counts.set(stream, (counts.get(stream) ?? 0) + values.length)
      for (const value of values) if (value && typeof value === 'object') {
        const row = value as Record<string, unknown>
        for (const key of ['location', 'world_id', 'worldId']) if (typeof row[key] === 'string' && row[key]) worldIds.add(String(row[key]))
        for (const key of ['user_id', 'userId', 'friend_id']) if (typeof row[key] === 'string' && row[key]) friendIds.add(String(row[key]))
      }
    }
    return { counts, worlds: worldIds.size, people: friendIds.size, total: [...counts.values()].reduce((a, b) => a + b, 0) }
  }, [chunks])
  const relatedRows = useMemo(() => detailEntity ? chunks.flatMap(chunk => Object.entries(chunk.body.streams).flatMap(([stream, values]) => values.filter(value => JSON.stringify(value).includes(detailEntity.id)).map(value => ({ stream, value })))) : [], [chunks, detailEntity])

  return <section className="card wide history-browser"><div className="section-heading"><div><h2>Encrypted history</h2><p className="muted">Vault manifests and chunks are verified and decrypted locally in a dedicated Worker. The browser sends no history content to the server.</p></div><Activity size={22} aria-hidden="true"/></div>
    {!unlocked ? <div className="empty-state">Your history is encrypted. Unlock your key under <a href="/dashboard/security">Security</a> to read it here.</div> : <>
      {error && <div className="alert error">{error}</div>}
      {notice && <div className="alert">{notice}</div>}
      {vaults.length>0&&<div className="history-controls"><label>Vault<select value={vaultId} onChange={event => {const selected=vaults.find(vault=>vault.vaultId===event.target.value);setVaultId(event.target.value);setManifest(null);setChunks([]);setBefore(selected?selected.maxSeq+1:0);setHasMore(false)}}>{vaults.map(vault => <option key={vault.vaultId} value={vault.vaultId}>{vault.vaultId} · {vault.maxSeq} chunks</option>)}</select></label><button disabled={!vaultId||busy} onClick={openNext}>{busy?'Verifying...':chunks.length?'Load earlier history':'Verify and open recent history'}</button><button disabled={busy} onClick={async()=>{await clearHistoryCache(accountId);setError('');setNotice('Local encrypted history cache cleared.')}}>Clear local cache</button></div>}
      {vaults.length>0&&vaultId&&<LivePanel vaultId={vaultId} accountId={accountId}/>}
      {!vaults.length && !error && <div className="empty-state">No synced vaults were found for this account.</div>}
      {chunks.length > 0 && <><p className="muted">Verified {chunks.length} chunks · {summaries.total} rows · {summaries.worlds} locations · {summaries.people} people</p><div className="history-view-tabs" role="tablist" aria-label="History views">{historyViews.map(item=><button key={item.id} role="tab" aria-selected={view===item.id} className={view===item.id?'selected':''} onClick={()=>{setView(item.id);setStreamFilter('')}}>{item.label}</button>)}</div>{view==='all'&&<div className="history-summary-grid">{[...summaries.counts].sort(([a],[b])=>a.localeCompare(b)).map(([stream,count])=><button key={stream} className="history-summary-card" onClick={()=>{setView(viewForStream(stream));setStreamFilter(stream)}}><strong>{count}</strong><span>{stream.replaceAll('_',' ')}</span></button>)}</div>}<div className="history-filters"><label>Search loaded rows<input type="search" value={query} onChange={event=>setQuery(event.target.value)} placeholder="Search names, locations, or text"/></label><label>Stream<select value={streamFilter} onChange={event=>setStreamFilter(event.target.value)}><option value="">All streams</option>{streams.filter(stream=>view==='all'||viewForStream(stream)===view).map(stream=><option key={stream}>{stream}</option>)}</select></label><label>From<input type="date" value={fromDate} onChange={event=>setFromDate(event.target.value)}/></label><label>Through<input type="date" value={throughDate} onChange={event=>setThroughDate(event.target.value)}/></label></div>{detailEntity&&<section className="entity-detail"><div className="section-heading"><div><h3>{detailEntity.kind} details</h3><p className="muted">{detailEntity.id} · {relatedRows.length} related verified records loaded</p></div><button onClick={()=>setDetailEntity(null)}>Close</button></div>{relatedRows.length?relatedRows.map((item,index)=><article key={`${item.stream}-${index}`}><strong>{item.stream.replaceAll('_',' ')}</strong><RecordDetails value={item.value} onSelect={setDetailEntity}/></article>):<p className="muted">No related records in the loaded history pages.</p>}</section>}{view==='graph'&&<MutualGraph rows={rows.map(row=>row.value)}/ >}{rows.length ? <div className="activity-timeline">{rows.map((row, index)=><article className="activity-entry" key={`${row.chunk.header.chunkId}-${row.stream}-${row.index}-${index}`}><div className="activity-entry-meta"><span>{historyViews.find(item=>item.id===viewForStream(row.stream))?.label} · {row.stream}</span><time><Clock3 size={13}/>{new Date(row.time).toLocaleString()}</time></div><ActivityRow stream={row.stream} value={row.value}/><details><summary><ChevronDown size={14}/>Record details</summary><RecordDetails value={row.value} onSelect={setDetailEntity}/></details></article>)}</div> : <div className="empty-state">No loaded events match these filters.</div>}</>}
      {hasMore&&<button disabled={busy} onClick={openNext}>Load earlier history</button>}
    </>}
  </section>
}

type LiveData = { own: { status: string; statusDescription: string; location: string }; friends: { userId: string; displayName: string; status: string; statusDescription: string; location: string; platform: string; lastSeenAtMs: number }[]; instances: { location: string; occupants: string[]; capacity?: number | null }[]; createdAtMs: number }

function LivePanel({ vaultId, accountId }: { vaultId: string; accountId: string }) {
  const [live, setLive] = useState<LiveData | null>(null)
  const [message, setMessage] = useState('Loading live presence...')
  const [age, setAge] = useState(0)
  useEffect(() => {
    let active = true
    let timer: ReturnType<typeof setTimeout>
    const refresh = async () => {
      try {
        const manifestResponse = await requestBinary(`/vaults/${encodeURIComponent(vaultId)}/manifest`)
        const manifestSeq = Number(manifestResponse.headers.get('x-manifest-seq'))
        if (!Number.isSafeInteger(manifestSeq) || manifestSeq < 1) throw new Error('Vault manifest sequence is invalid.')
        const manifest = encode64url(new Uint8Array(await manifestResponse.arrayBuffer()))
        const response = await requestBinary(`/vaults/${encodeURIComponent(vaultId)}/live`)
        const liveSeq = Number(response.headers.get('x-live-seq'))
        if (!Number.isSafeInteger(liveSeq) || liveSeq < 1) throw new Error('Live snapshot sequence is invalid.')
        const blob = encode64url(new Uint8Array(await response.arrayBuffer()))
        const rollbackKey = `remotesync.manifest-seq.${accountId}.${vaultId}`
        const saved = Number(localStorage.getItem(rollbackKey) ?? 0)
        const highestManifestSeq = Number.isSafeInteger(saved) && saved > 0 ? saved : null
        const opened = await verifyAndOpenLive({ vaultId, manifestSeq, highestManifestSeq, manifest, liveSeq, blob }) as LiveData
        if (!active) return
        localStorage.setItem(rollbackKey, String(Math.max(saved || 0, manifestSeq)))
        setLive(opened); setAge(Number(response.headers.get('x-live-age') ?? 0)); setMessage('')
      } catch (error) {
        if (!active) return
        const reason = (error as Error).message
        setMessage(reason.includes('No live snapshot') ? 'No live snapshot is available. The collector may be stopped or still connecting.' : reason)
      }
      if (active) timer = setTimeout(refresh, 30_000)
    }
    void refresh()
    return () => { active = false; clearTimeout(timer) }
  }, [vaultId, accountId])
  return <section className="live-panel" aria-live="polite"><div className="section-heading"><div><h3>Live presence</h3><p className="muted">Decrypted and signature-checked in this browser · refreshes every 30 seconds</p></div>{live&&<span className="live-age">Updated {age}s ago</span>}</div>{message&&<p className="muted">{message}</p>}{live&&<><div className="live-own"><strong>You</strong><span>{live.own.status||'Unknown status'}{live.own.statusDescription?` · ${live.own.statusDescription}`:''}</span><span>{live.own.location||'Not in an instance'}</span></div><h4>Friends online ({live.friends.length})</h4>{live.friends.length===0?<p className="muted">No friend presence was included in this snapshot.</p>:<div className="live-friends">{live.friends.map(friend=><article key={friend.userId}><strong>{friend.displayName||friend.userId}</strong><span>{friend.status}{friend.statusDescription?` · ${friend.statusDescription}`:''}</span><small>{friend.location||'Offline'}{friend.platform?` · ${friend.platform}`:''}</small></article>)}</div>}{live.instances.length>0&&<><h4>Shared instances</h4><div className="live-friends">{live.instances.map(instance=><article key={instance.location}><strong>{instance.location}</strong><span>{instance.occupants.length}{instance.capacity?` / ${instance.capacity}`:''} occupants</span><small>{instance.occupants.join(', ')}</small></article>)}</div></>}</>}</section>
}

function rowTime(value: unknown, fallback: number) {
  if (!value || typeof value !== 'object') return fallback
  const row = value as Record<string, unknown>
  for (const key of ['timestampMs', 'createdAtMs', 'occurredAtMs', 'timeMs', 'dateMs']) {
    const candidate = row[key]
    if (typeof candidate === 'number' && Number.isFinite(candidate)) return candidate
  }
  for (const key of ['timestamp', 'createdAt', 'occurredAt', 'time', 'date']) {
    const candidate = row[key]
    if (typeof candidate === 'string' || typeof candidate === 'number') {
      const parsed = new Date(candidate).getTime()
      if (Number.isFinite(parsed)) return parsed
    }
  }
  return fallback
}

function localDateBoundary(value: string, nextDay = false) {
  const date = new Date(`${value}T00:00:00`)
  if (nextDay) date.setDate(date.getDate() + 1)
  return date.getTime()
}

function ActivityRow({ stream, value }: { stream: string; value: unknown }) {
  if (!value || typeof value !== 'object') return <p className="activity-entry-summary">{String(value)}</p>
  const row = value as Record<string, unknown>
  const date = String(row.created_at ?? row.createdAt ?? row.created_at_ms ?? '')
  if (stream === 'feed_status') return <div className="activity-entry-summary"><strong>Status changed{row.status ? ` to ${row.status}` : ''}</strong><p>{String(row.status_description ?? row.statusDescription ?? 'No status description')}</p></div>
  if (stream === 'feed_gps') return <div className="activity-entry-summary"><strong>Location changed</strong><p>{String(row.location ?? row.world_name ?? row.worldName ?? 'Unknown location')}{row.world_id || row.worldId ? ` · ${row.world_id ?? row.worldId}` : ''}</p></div>
  if (stream === 'feed_bio' || stream === 'profile_bio') return <div className="activity-entry-summary"><strong>Bio updated</strong><p>{String(row.bio ?? row.description ?? 'Bio content unavailable')}</p></div>
  if (stream === 'feed_avatar' || stream === 'avatar_history') return <div className="activity-entry-summary"><strong>{String(row.avatar_name ?? row.avatarName ?? row.name ?? 'Avatar changed')}</strong><p>{String(row.avatar_id ?? row.avatarId ?? '')}</p></div>
  if (stream === 'friend_log_history') return <div className="activity-entry-summary"><strong>{String(row.display_name ?? row.displayName ?? row.user_id ?? row.userId ?? 'Friend activity')}</strong><p>{String(row.type ?? row.event_type ?? 'Friend list changed')}{date ? ` · ${date}` : ''}</p></div>
  if (stream.startsWith('notifications')) return <div className="activity-entry-summary"><strong>{String(row.message ?? row.sender_name ?? row.senderName ?? row.type ?? 'Notification')}</strong><p>{String(row.message ?? row.details ?? row.sender_id ?? row.senderId ?? '')}</p></div>
  if (stream === 'moderation') return <div className="activity-entry-summary"><strong>{String(row.type ?? row.event ?? 'Moderation event')}</strong><p>{String(row.display_name ?? row.displayName ?? row.user_id ?? row.userId ?? row.reason ?? '')}</p></div>
  if (stream.startsWith('gamelog_')) return <div className="activity-entry-summary"><strong>{String(row.world_name ?? row.worldName ?? row.event_name ?? row.eventName ?? row.type ?? stream.replace('gamelog_',''))}</strong><p>{String(row.location ?? row.world_id ?? row.worldId ?? row.message ?? '')}</p></div>
  const primary = ['displayName', 'name', 'title', 'worldName', 'userName', 'message', 'event', 'type'].find(key => typeof row[key] === 'string' && row[key])
  const secondary = ['location', 'worldId', 'userId', 'description', 'status', 'platform'].filter(key => typeof row[key] === 'string' && row[key] && key !== primary).slice(0, 3)
  return <div className="activity-entry-summary"><strong>{primary ? String(row[primary]) : 'Recorded event'}</strong>{secondary.length > 0 && <p>{secondary.map(key => String(row[key])).join(' · ')}</p>}</div>
}

function RecordDetails({ value, onSelect }: { value: unknown; onSelect?: (entity: { id: string; kind: string }) => void }) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return <pre>{JSON.stringify(value, null, 2)}</pre>
  const entries = Object.entries(value as Record<string, unknown>).filter(([, field]) => field !== null && field !== undefined && field !== '')
  return <dl className="record-details">{entries.map(([key, field])=><React.Fragment key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{typeof field === 'object' ? JSON.stringify(field) : isEntityId(key, field) ? <button className="inline-entity" onClick={()=>onSelect?.({id:String(field),kind:key.toLowerCase().includes('world')||key.toLowerCase().includes('location')?'World':key.toLowerCase().includes('avatar')?'Avatar':'User'})}>{String(field)} · related records</button> : String(field)}</dd></React.Fragment>)}</dl>
}

function isEntityId(key: string, value: unknown) { return typeof value === 'string' && /^(user|friend|world|avatar).*(id)$/i.test(key) && value.length > 3 }

function MutualGraph({ rows }: { rows: unknown[] }) {
  const users = new Set<string>()
  const links = new Set<string>()
  for (const value of rows) if (value && typeof value === 'object') {
    const row = value as Record<string, unknown>
    const user = String(row.user_id ?? row.userId ?? row.friend_id ?? row.friendId ?? '')
    const other = String(row.friend_user_id ?? row.friendUserId ?? row.other_user_id ?? row.otherUserId ?? '')
    if (user) users.add(user)
    if (other) { users.add(other); links.add([user,other].sort().join(' ')) }
  }
  const nodes=[...users].sort()
  const points=new Map(nodes.map((user,index)=>{const angle=(2*Math.PI*index/Math.max(nodes.length,1))-(Math.PI/2);return[user,{x:300+Math.cos(angle)*135,y:180+Math.sin(angle)*135}] as const}))
  const pairs=[...links].map(link=>link.split(' '))
  return <div className="history-graph-summary"><strong>{users.size} people · {links.size} known links</strong><p className="muted">The graph is built only from mutual friend rows present in the loaded, verified chunks.</p>{nodes.length?<svg className="mutual-graph" viewBox="0 0 600 360" role="img" aria-label={`Mutual friends graph with ${nodes.length} people and ${links.size} links`}>{pairs.map(([a,b])=>{const p=points.get(a),q=points.get(b);return p&&q?<line key={`${a}-${b}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y}/>:null})}{nodes.map(user=>{const p=points.get(user)!;return <g key={user}><circle cx={p.x} cy={p.y} r="8"/><text x={p.x} y={p.y+24} textAnchor="middle">{user}</text></g>})}</svg>:<div className="empty-state">No mutual friend relationships were included in the loaded history.</div>}</div>
}

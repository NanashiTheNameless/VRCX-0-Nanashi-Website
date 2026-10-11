import { useEffect, useState } from 'react'
import { publicGet } from './api'
import { ImagesToggle, useImagesEnabled } from './images'
import { SitePage, WEBSITE_SOURCE } from './site'

type Theme = { id: string; name: string; version: string; description: string; tags: string[]; author: { name: string; github: string } }

const CATALOG = 'https://raw.githubusercontent.com/Map1en/VRCX-0-Community-Themes/master/themes'
const REPOSITORY = 'https://github.com/Map1en/VRCX-0-Community-Themes/tree/master/themes'
const THEME_ID = /^[a-z0-9]+(-[a-z0-9]+)*$/
const text = (value: unknown, limit: number) => (typeof value === 'string' ? value.slice(0, limit) : '')

function parseTheme(entry: any, fallbackId: string): Theme | null {
  const id = text(entry?.id, 64) || fallbackId
  if (!THEME_ID.test(id)) return null
  return {
    id,
    name: text(entry?.name, 120) || id,
    version: text(entry?.version, 32),
    description: text(entry?.description, 500),
    tags: Array.isArray(entry?.tags) ? entry.tags.map((tag: unknown) => text(tag, 32)).filter(Boolean).slice(0, 8) : [],
    author: { name: text(entry?.author?.name, 80), github: text(entry?.author?.github, 80) },
  }
}

const github = (path: string) => fetch(`${CATALOG}/${path}`, { referrerPolicy: 'no-referrer', credentials: 'omit' })

async function loadCatalog(): Promise<Theme[]> {
  const response = await github('index.json')
  if (!response.ok) throw new Error(`GitHub returned ${response.status}.`)
  const listed = (await response.json() as { themes?: unknown })?.themes
  if (!Array.isArray(listed)) return []
  const themes = await Promise.all(listed.slice(0, 128).map(async (entry: unknown) => {
    if (typeof entry !== 'string') return parseTheme(entry, '')
    if (!THEME_ID.test(entry)) return null
    const manifest = await github(`${entry}/theme.json`).then(result => result.ok ? result.json() : null).catch(() => null)
    return parseTheme(manifest, entry)
  }))
  return themes.filter((theme): theme is Theme => theme !== null)
}

export function Themes() {
  const [themes, setThemes] = useState<Theme[] | null>(null)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const images = useImagesEnabled()
  useEffect(() => {
    let active = true
    loadCatalog()
      .then(result => { if (active) setThemes(result) })
      .catch(cause => { if (active) setError((cause as Error).message) })
    return () => { active = false }
  }, [])
  const needle = query.trim().toLowerCase()
  const shown = (themes ?? []).filter(theme => !needle || [theme.name, theme.description, theme.author.name, ...theme.tags].some(value => value.toLowerCase().includes(needle)))

  return (
    <SitePage title="Themes">
      <header className="public-header">
        <div className="eyebrow">COMMUNITY</div>
        <h1>Themes</h1>
        <p className="muted">Community themes for VRCX-0-Nanashi. This page loads the catalog and previews directly from GitHub, so GitHub sees those requests. Nothing is counted or reported here. Install a theme in the app under Settings, Interface, Themes.</p>
        <div className="button-row">
          <input type="search" aria-label="Search themes" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search themes" />
          <ImagesToggle />
        </div>
      </header>
      {error && <div className="alert error">The theme catalog could not be loaded. {error}</div>}
      {!themes && !error && <div className="empty-state">Loading themes...</div>}
      <div className="world-grid">
        {shown.map(theme => (
          <article className="card world" key={theme.id}>
            {images && <img src={`${CATALOG}/${theme.id}/preview.webp`} alt="" loading="lazy" referrerPolicy="no-referrer" />}
            <div className="eyebrow">{theme.tags.join(' / ') || 'THEME'}</div>
            <h2>{theme.name}</h2>
            <p className="muted">{theme.author.name && `By ${theme.author.name}`}{theme.version && ` (version ${theme.version})`}</p>
            {theme.description && <p>{theme.description}</p>}
            <p><a href={`${REPOSITORY}/${theme.id}`} rel="noreferrer">View source on GitHub</a></p>
          </article>
        ))}
      </div>
      {themes && shown.length === 0 && <div className="empty-state">{themes.length === 0 ? 'The catalog lists no themes right now.' : 'No themes match this search.'}</div>}
    </SitePage>
  )
}

export function Licenses() {
  return (
    <SitePage title="Licenses">
      <header className="public-header">
        <div className="eyebrow">LEGAL</div>
        <h1>Licenses</h1>
      </header>
      <article className="card">
        <h2>VRCX-0-Nanashi-Website</h2>
        <p>Copyright (C) 2026 NamelessNanashi. Licensed under the GNU General Public License v3.0 only.</p>
        <p><a href={WEBSITE_SOURCE} rel="noreferrer">Source code</a> and <a href="https://www.gnu.org/licenses/gpl-3.0.txt" rel="noreferrer">license text</a>.</p>
      </article>
      <article className="card wide">
        <h2>0xProto</h2>
        <p>The 0xProto font, Copyright (c) 2026 0xType Project Authors, is bundled under the SIL Open Font License 1.1.</p>
        <p><a href="https://github.com/0xType/0xProto" rel="noreferrer">Project</a> and <a href="https://openfontlicense.org/open-font-license-official-text/" rel="noreferrer">license text</a>.</p>
      </article>
      <article className="card wide">
        <h2>EFF word list</h2>
        <p>Generated word passphrases use the EFF Large Wordlist for Passphrases by the Electronic Frontier Foundation, licensed under Creative Commons Attribution 3.0 United States.</p>
        <p><a href="https://www.eff.org/dice" rel="noreferrer">Source</a> and <a href="https://creativecommons.org/licenses/by/3.0/us/" rel="noreferrer">license</a>.</p>
      </article>
      <article className="card wide">
        <h2>Other components</h2>
        <p>The website also includes React, ALTCHA, noble-ciphers, hash-wasm, and zxcvbn (MIT), Lucide icons (ISC), and Rust libraries compiled to WebAssembly, each under its own open-source license. Every dependency and its version is listed in package-lock.json and Cargo.lock in the source repository.</p>
      </article>
    </SitePage>
  )
}

type SharedWorld = { world_id: string; name: string; author_name: string; image_url: string; description: string; comment: string }
type SharedCollection = { title: string; note: string | null; author_name: string; category: string | null; updated_at: number; worlds: SharedWorld[] }
type ListedCollection = { id: string; title: string; category: string | null; updated_at: number }

const day = (seconds: number) => new Date(seconds * 1000).toLocaleDateString()

export function PublicCollection({ code }: { code: string }) {
  const images = useImagesEnabled()
  const [collection, setCollection] = useState<SharedCollection | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    publicGet<SharedCollection>(`/collections/${encodeURIComponent(code)}`)
      .then(result => { if (active) setCollection(result) })
      .catch(cause => { if (active) setError((cause as Error).message) })
    return () => { active = false }
  }, [code])

  return (
    <SitePage title={collection?.title ?? 'Shared collection'}>
      {error ? <article className="card"><h1>Collection unavailable</h1><p className="muted">{error}</p><a className="button" href="/collections">Browse collections</a></article>
        : !collection ? <div className="empty-state">Loading collection...</div> : (
          <>
            <header className="public-header">
              <div className="eyebrow">SHARED WORLD COLLECTION</div>
              <h1>{collection.title}</h1>
              <p className="muted">By {collection.author_name}{collection.category ? ` in ${collection.category}` : ''}, {collection.worlds.length} {collection.worlds.length === 1 ? 'world' : 'worlds'}, updated {day(collection.updated_at)}</p>
              {collection.note && <p>{collection.note}</p>}
              <div className="button-row">
                <a className="button primary" href={`vrcx-0-nanashi://collection/import?id=${encodeURIComponent(code)}`}>Import into VRCX-0-Nanashi</a>
                <ImagesToggle />
              </div>
            </header>
            {collection.worlds.length === 0 && <div className="empty-state">This collection has no worlds yet.</div>}
            <div className="world-grid">
              {collection.worlds.map(world => (
                <article className="card world" key={world.world_id}>
                  {images && world.image_url && <img src={world.image_url} alt="" loading="lazy" referrerPolicy="no-referrer" />}
                  <h2>{world.name || 'Unnamed world'}</h2>
                  {world.author_name && <p className="muted">By {world.author_name}</p>}
                  {world.description && <p>{world.description}</p>}
                  {world.comment && <div className="world-comment">{world.comment}</div>}
                  <p className="relay-id">{world.world_id}</p>
                  <p><a href={`https://vrchat.com/home/world/${encodeURIComponent(world.world_id)}`} rel="noreferrer">Open on the VRChat website</a></p>
                </article>
              ))}
            </div>
          </>
        )}
    </SitePage>
  )
}

export function PublicDirectory() {
  const [items, setItems] = useState<ListedCollection[] | null>(null)
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    const needle = query.trim()
    const timer = setTimeout(() => {
      publicGet<ListedCollection[]>(`/collections${needle ? `?q=${encodeURIComponent(needle)}` : ''}`)
        .then(result => { if (active) { setItems(result); setError('') } })
        .catch(cause => { if (active) setError((cause as Error).message) })
    }, needle ? 250 : 0)
    return () => { active = false; clearTimeout(timer) }
  }, [query])

  return (
    <SitePage title="World collections">
      <header className="public-header">
        <div className="eyebrow">COMMUNITY</div>
        <h1>World collections</h1>
        <p className="muted">World collections that RemoteSync users chose to list publicly. Share your own from VRCX-0-Nanashi or from the dashboard.</p>
        <input type="search" aria-label="Search collections" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search collections" />
      </header>
      {error && <div className="alert error">The collection list could not be loaded. {error}</div>}
      {!items && !error && <div className="empty-state">Loading collections...</div>}
      <div className="world-grid">
        {(items ?? []).map(item => (
          <a className="card collection-card" href={`/c/${encodeURIComponent(item.id)}`} key={item.id}>
            <div className="eyebrow">{item.category || 'COLLECTION'}</div>
            <h2>{item.title}</h2>
            <p className="muted">Updated {day(item.updated_at)}</p>
          </a>
        ))}
      </div>
      {items && items.length === 0 && !error && <div className="empty-state">{query.trim() ? 'No listed collections match this search.' : 'No collections are listed yet.'}</div>}
    </SitePage>
  )
}

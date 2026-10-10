import { useEffect, useState } from 'react'
import { Waves } from 'lucide-react'
import { ImagesToggle, useImagesEnabled } from './images'

type Theme = { id: string; name: string; version: string; description: string; tags: string[]; author: { name: string; github: string } }

const CATALOG = 'https://raw.githubusercontent.com/Map1en/VRCX-0-Community-Themes/master/themes'
const REPOSITORY = 'https://github.com/Map1en/VRCX-0-Community-Themes/tree/master/themes'
const THEME_ID = /^[a-z0-9]+(-[a-z0-9]+)*$/
const text = (value: unknown, limit: number) => (typeof value === 'string' ? value.slice(0, limit) : '')

function parseCatalog(data: unknown): Theme[] {
  const themes = (data as { themes?: unknown })?.themes
  if (!Array.isArray(themes)) return []
  return themes.slice(0, 128).flatMap(entry => {
    const id = text(entry?.id, 64)
    if (!THEME_ID.test(id)) return []
    return [{
      id,
      name: text(entry.name, 120) || id,
      version: text(entry.version, 32),
      description: text(entry.description, 500),
      tags: Array.isArray(entry.tags) ? entry.tags.map((tag: unknown) => text(tag, 32)).filter(Boolean).slice(0, 8) : [],
      author: { name: text(entry.author?.name, 80), github: text(entry.author?.github, 80) },
    }]
  })
}

function Shell({ children }: { children: React.ReactNode }) {
  return <main className="public-shell"><a className="brand" href="/"><Waves size={22}/> RemoteSync</a>{children}</main>
}

export function Themes() {
  const [themes, setThemes] = useState<Theme[] | null>(null)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const images = useImagesEnabled()
  useEffect(() => {
    fetch(`${CATALOG}/index.json`, { referrerPolicy: 'no-referrer', credentials: 'omit' })
      .then(response => { if (!response.ok) throw new Error(`GitHub returned ${response.status}.`); return response.json() })
      .then(data => setThemes(parseCatalog(data)))
      .catch(cause => setError((cause as Error).message))
  }, [])
  const needle = query.trim().toLowerCase()
  const shown = (themes ?? []).filter(theme => !needle || [theme.name, theme.description, theme.author.name, ...theme.tags].some(value => value.toLowerCase().includes(needle)))

  return (
    <Shell>
      <header className="public-header">
        <div className="eyebrow">COMMUNITY</div>
        <h1>Themes</h1>
        <p className="muted">Community themes for VRCX-0-Nanashi. This page loads the catalog and previews directly from GitHub, so GitHub sees those requests. Nothing is counted or reported here. Install a theme in the app under Settings, Interface, Themes.</p>
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search themes" />
        <ImagesToggle />
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
      {themes && shown.length === 0 && <div className="empty-state">No themes match.</div>}
    </Shell>
  )
}

export function Licenses() {
  return (
    <Shell>
      <header className="public-header">
        <div className="eyebrow">LEGAL</div>
        <h1>Licenses</h1>
      </header>
      <article className="card">
        <h2>VRCX-0-Nanashi-Website</h2>
        <p>Copyright (C) 2026 NamelessNanashi. Licensed under the GNU General Public License v3.0 only.</p>
        <p><a href="https://github.com/NanashiTheNameless/VRCX-0-Nanashi-Website" rel="noreferrer">Source code</a> and <a href="https://www.gnu.org/licenses/gpl-3.0.txt" rel="noreferrer">license text</a>.</p>
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
        <p>The website also includes React, noble-ciphers, hash-wasm, and zxcvbn (MIT), Lucide icons (ISC), and Rust libraries compiled to WebAssembly, each under its own open-source license. Every dependency and its version is listed in package-lock.json and Cargo.lock in the source repository.</p>
      </article>
    </Shell>
  )
}

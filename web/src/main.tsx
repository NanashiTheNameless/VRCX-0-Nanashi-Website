import React, { lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { ArrowUpRight } from 'lucide-react'
import { RelayPage } from './relay'
import { Licenses, PublicCollection, PublicDirectory, Themes } from './publicPages'
import { APP_SOURCE, DOWNLOAD, SitePage, WEBSITE_SOURCE } from './site'
import './styles/fonts-0xproto.css'
import './styles/app.css'

const Dashboard = lazy(() => import('./dashboard'))

const FEATURES = [
  ['No telemetry', 'No analytics, crash reporting, or usage reporting. The app talks to VRChat, GitHub, and the services you turn on.'],
  ['RemoteSync', 'Optional end-to-end encrypted history sync between your PCs. Off by default, and the server cannot read what it stores.'],
  ['Shared collections', 'Publish a list of worlds as a link that anyone can open and import, without a VRChat user id attached.'],
  ['Runs next to VRCX-0', 'Its own data folder, links, and updates. Your VRCX-0 data is copied on first launch and never written to.'],
] as const

function LandingPage() {
  return (
    <SitePage title="" className="landing-main">
      <section className="landing-hero">
        <div className="landing-copy">
          <h1>VRCX-0-Nanashi</h1>
          <p>A personal fork of VRCX-0, the companion app for VRChat, with its own encrypted history sync and no telemetry.</p>
          <div className="landing-actions">
            <a className="landing-button primary" href={DOWNLOAD} target="_blank" rel="noreferrer">Download <ArrowUpRight size={16} aria-hidden="true" /></a>
            <a className="landing-button secondary" href="/dashboard">Open dashboard</a>
            <a className="landing-button secondary" href="/collections">Browse collections</a>
          </div>
        </div>
        <img className="landing-logo" src="/vrcx-0-nanashi.png" alt="VRCX-0-Nanashi app icon" />
      </section>
      <section className="landing-features" aria-label="Highlights">
        {FEATURES.map(([name, text]) => <article key={name}><h2>{name}</h2><p>{text}</p></article>)}
      </section>
    </SitePage>
  )
}

function PrivacyPage() {
  return (
    <SitePage title="Privacy" className="privacy-content">
      <h1>Privacy</h1>
      <p>VRCX-0-Nanashi is open source. Read the source code to see how the desktop app and RemoteSync service handle information.</p>
      <ul>
        <li><a href={APP_SOURCE} target="_blank" rel="noreferrer">Desktop app source code</a></li>
        <li><a href={WEBSITE_SOURCE} target="_blank" rel="noreferrer">RemoteSync website and server source code</a></li>
      </ul>
      <p>Source code describes the software. A self-hosted RemoteSync server's operator controls its hosting and configuration.</p>
      <a className="landing-button secondary" href="/">Back to home</a>
    </SitePage>
  )
}

function NotFoundPage() {
  return (
    <SitePage title="Page not found" className="landing-main">
      <section className="landing-hero">
        <div className="landing-copy">
          <div className="eyebrow">404</div>
          <h1>Page not found</h1>
          <p>This page does not exist or has moved.</p>
          <div className="landing-actions"><a className="landing-button primary" href="/">Back to home</a></div>
        </div>
        <img className="landing-logo" src="/vrcx-0-nanashi.png" alt="" />
      </section>
    </SitePage>
  )
}

const DASHBOARD_PATHS = [
  '/dashboard',
  ...['devices', 'pair', 'data', 'collections', 'security', 'collector', 'admin'].map(page => `/dashboard/${page}`),
  '/pair',
  '/invite',
  '/verify',
  '/reset',
]

function App() {
  const path = location.pathname
  if (path === '/') return <LandingPage />
  if (path === '/privacy') return <PrivacyPage />
  if (path === '/themes') return <Themes />
  if (path === '/licenses') return <Licenses />
  if (path === '/collections') return <PublicDirectory />
  if (path.startsWith('/open/')) return <RelayPage />
  if (path.startsWith('/c/')) return <PublicCollection code={path.split('/')[2] ?? ''} />
  if (!DASHBOARD_PATHS.includes(path)) return <NotFoundPage />
  return <Suspense fallback={<main className="auth-shell"><p className="muted">Loading...</p></main>}><Dashboard /></Suspense>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)

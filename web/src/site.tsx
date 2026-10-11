import { useEffect, type ReactNode } from 'react'
import { ArrowUpRight } from 'lucide-react'

export const SITE_NAME = 'VRCX-0-Nanashi'
export const APP_SOURCE = 'https://github.com/NanashiTheNameless/VRCX-0-Nanashi'
export const WEBSITE_SOURCE = 'https://github.com/NanashiTheNameless/VRCX-0-Nanashi-Website'
export const DOWNLOAD = `${APP_SOURCE}/releases/tag/Nightly-Rolling`

const NAV = [
  ['/collections', 'Collections'],
  ['/themes', 'Themes'],
  ['/dashboard', 'Dashboard'],
] as const

export function useTitle(title: string) {
  useEffect(() => {
    document.title = title ? `${title} - ${SITE_NAME}` : SITE_NAME
  }, [title])
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let index = -1
  do {
    value /= 1024
    index++
  } while (value >= 1024 && index < units.length - 1)
  return `${value.toFixed(1)} ${units[index]}`
}

function Brand() {
  return <a className="landing-brand" href="/"><img className="landing-mark" src="/vrcx-0-nanashi.png" alt="" /><span>VRCX-0-NANASHI</span></a>
}

export function SiteHeader() {
  const path = location.pathname
  return (
    <header className="landing-nav">
      <Brand />
      <nav aria-label="Main navigation">
        {NAV.map(([href, label]) => <a key={href} href={href} aria-current={path === href ? 'page' : undefined}>{label}</a>)}
        <a href={APP_SOURCE} target="_blank" rel="noreferrer">Source <ArrowUpRight size={14} aria-hidden="true" /></a>
      </nav>
    </header>
  )
}

export function SiteFooter() {
  return (
    <footer className="landing-footer">
      <Brand />
      <a href="/privacy">Privacy</a>
      <a href="/licenses">Licenses</a>
      <a href={WEBSITE_SOURCE} target="_blank" rel="noreferrer">Website source</a>
    </footer>
  )
}

export function SitePage({ title, className, children }: { title: string; className?: string; children: ReactNode }) {
  useTitle(title)
  return (
    <div className="landing-shell">
      <SiteHeader />
      <main className={className ?? 'public-shell'}>{children}</main>
      <SiteFooter />
    </div>
  )
}

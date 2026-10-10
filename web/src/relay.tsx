import { Waves } from 'lucide-react'
import { ImagesToggle, useImagesEnabled } from './images'
import { appLink, parseRelayLocation, vrchatLink } from './relayLinks'

const TITLES = { world: 'VRChat world', avatar: 'VRChat avatar', instance: 'VRChat instance' }

export function RelayPage() {
  const images = useImagesEnabled()
  const target = parseRelayLocation(location.pathname, location.search, location.hash)
  if (!target) {
    return <main className="public-shell"><a className="brand" href="/"><Waves size={22}/> RemoteSync</a>
      <article className="card"><h1>Link not recognized</h1><p className="muted">This link is not a valid world, avatar, or instance link.</p></article>
    </main>
  }
  const preview = target.kind === 'instance' ? null : target.preview
  const id = target.kind === 'instance' ? target.worldId : target.id
  const hasPreview = Boolean(preview && (preview.name || preview.author || preview.imageUrl))
  return <main className="public-shell"><a className="brand" href="/"><Waves size={22}/> RemoteSync</a>
    <article className="card world relay">
      {images && preview?.imageUrl && <img src={preview.imageUrl} alt="" referrerPolicy="no-referrer"/>}
      <div className="eyebrow">{TITLES[target.kind].toUpperCase()}</div>
      <h1>{preview?.name || TITLES[target.kind]}</h1>
      {preview?.author && <p className="muted">By {preview.author}</p>}
      <p className="relay-id">{id}{target.kind === 'instance' && `:${target.instanceId}`}</p>
      {hasPreview && <small>Shared by the person who sent this link. It was not checked by this website.</small>}
      <div className="relay-actions">
        <a className="button primary" href={appLink(target)}>Open in VRCX-0-Nanashi</a>
        <a className="button" href={vrchatLink(target)} rel="noreferrer">Open on the VRChat website</a>
      </div>
      {preview?.imageUrl && <ImagesToggle/>}
    </article>
  </main>
}

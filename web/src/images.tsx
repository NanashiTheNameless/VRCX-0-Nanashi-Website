import { useEffect, useState } from 'react'

const KEY = 'remotesync.images'
const EVENT = 'remotesync-images'
const read = () => localStorage.getItem(KEY) !== 'off'

export function useImagesEnabled() {
  const [enabled, setEnabled] = useState(read)
  useEffect(() => {
    const update = () => setEnabled(read())
    window.addEventListener(EVENT, update)
    return () => window.removeEventListener(EVENT, update)
  }, [])
  return enabled
}

export function ImagesToggle() {
  const enabled = useImagesEnabled()
  const toggle = () => {
    localStorage.setItem(KEY, enabled ? 'off' : 'on')
    window.dispatchEvent(new Event(EVENT))
  }
  return <button className="link" onClick={toggle}>{enabled ? 'Turn images off' : 'Turn images on'}</button>
}

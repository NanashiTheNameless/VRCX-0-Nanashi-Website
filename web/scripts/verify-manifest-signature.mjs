import { createPublicKey, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'

const root = new URL('../dist/', import.meta.url)
const manifest = await readFile(new URL('web-manifest.json', root))
const signature = Buffer.from((await readFile(new URL('web-manifest.sig', root), 'utf8')).trim(), 'base64')
const publicKey = createPublicKey({ key: Buffer.from('MCowBQYDK2VwAyEAZFMdbH5lgJK5hR3tqn3VwFJEZj7qXncSFgpV88pfKsk=', 'base64'), format: 'der', type: 'spki' })
if (!verify(null, manifest, publicKey, signature)) throw new Error('website manifest signature does not match the desktop-pinned key')
console.log('Website manifest signature matches the desktop-pinned key.')

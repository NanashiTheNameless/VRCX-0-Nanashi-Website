import { sign } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const privateKey = process.env.WEBSITE_MANIFEST_PRIVATE_KEY
if (!privateKey) throw new Error('WEBSITE_MANIFEST_PRIVATE_KEY is required')
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = await readFile(resolve(root, 'dist/web-manifest.json'))
const signature = sign(null, manifest, privateKey)
await writeFile(resolve(root, 'dist/web-manifest.sig'), `${signature.toString('base64')}\n`)

import { createHash } from 'node:crypto'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'

const root = resolve('dist')
const files = []
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) await walk(path)
    else {
      const name = relative(root, path).split('\\').join('/')
      const bytes = await readFile(path)
      if (name !== 'web-manifest.json' && name !== 'web-manifest.sig') {
        files.push({ path: name, sha256: createHash('sha256').update(bytes).digest('hex') })
      }
    }
  }
}
await walk(root)
files.sort((a, b) => a.path.localeCompare(b.path))
const generated = JSON.stringify({
  version: process.env.npm_package_version ?? '0.1.0',
  sourceCommit: process.env.SOURCE_COMMIT ?? process.env.GITHUB_SHA ?? 'unknown',
  files,
}, null, 2) + '\n'
const manifestPath = join(root, 'web-manifest.json')
const signaturePath = join(root, 'web-manifest.sig')
let suppliedManifest
let suppliedSignature
try {
  suppliedManifest = await readFile(manifestPath, 'utf8')
} catch (error) {
  if (error.code !== 'ENOENT') throw error
}
try {
  suppliedSignature = await readFile(signaturePath, 'utf8')
} catch (error) {
  if (error.code !== 'ENOENT') throw error
}
if (process.env.SIGNED_MANIFEST === '1') {
  if (!suppliedManifest || !suppliedSignature?.trim()) {
    throw new Error('signed website manifest and signature were required but not supplied')
  }
  if (suppliedManifest !== generated) {
    throw new Error('supplied website manifest does not match this build')
  }
} else {
  if (suppliedManifest || suppliedSignature) {
    throw new Error('signed website metadata was supplied to an unsigned build')
  }
  await writeFile(manifestPath, generated)
}

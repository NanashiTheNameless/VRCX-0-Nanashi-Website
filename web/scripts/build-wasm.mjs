import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const webDir = resolve(fileURLToPath(new URL('..', import.meta.url)))
const repoDir = resolve(webDir, '..')
if (process.env.REMOTESYNC_SKIP_WASM_BUILD !== '1') {
  execFileSync('rustup', ['target', 'add', 'wasm32-unknown-unknown'], { cwd: repoDir, stdio: 'inherit' })
  execFileSync('cargo', ['build', '--release', '-p', 'vrcx-0-nanashi-website-protocol-wasm', '--target', 'wasm32-unknown-unknown'], { cwd: repoDir, stdio: 'inherit' })
}
mkdirSync(resolve(webDir, 'public'), { recursive: true })
const wasmOutput = resolve(webDir, 'public/remotesync_protocol.wasm')
if (process.env.REMOTESYNC_SKIP_WASM_BUILD === '1') {
  if (!existsSync(wasmOutput)) throw new Error(`Missing prebuilt protocol WASM: ${wasmOutput}`)
} else {
  copyFileSync(resolve(repoDir, 'target/wasm32-unknown-unknown/release/vrcx_0_nanashi_website_protocol_wasm.wasm'), wasmOutput)
}

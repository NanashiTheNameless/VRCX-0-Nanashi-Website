import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const userscript = await readFile(new URL('../../userscript/remotesync-verify.user.js', import.meta.url), 'utf8')
const keys = name => JSON.parse(userscript.match(new RegExp(`const ${name} = (\\[[^\\]]*\\])`))[1].replaceAll("'", '"'))

test('the userscript pins valid Ed25519 keys that differ between code and instance', async () => {
  const code = keys('CODE_KEYS')
  const instance = keys('INSTANCE_KEYS')
  assert.ok(code.length > 0 && instance.length > 0)
  assert.equal(code.some(key => instance.includes(key)), false)
  for (const key of [...code, ...instance]) {
    await crypto.subtle.importKey('spki', Buffer.from(key, 'base64'), { name: 'Ed25519' }, false, ['verify'])
  }
})

test('the userscript can verify a statement signed the same way the signing script does', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const message = new TextEncoder().encode('{"v":1}')
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, message)
  const spki = Buffer.from(await crypto.subtle.exportKey('spki', pair.publicKey)).toString('base64')
  const imported = await crypto.subtle.importKey('spki', Buffer.from(spki, 'base64'), { name: 'Ed25519' }, false, ['verify'])
  assert.equal(await crypto.subtle.verify({ name: 'Ed25519' }, imported, signature, message), true)
})

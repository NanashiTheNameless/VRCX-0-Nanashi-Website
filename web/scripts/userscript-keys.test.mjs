import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runInNewContext } from 'node:vm'

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

test('instance verification reads seconds and original millisecond statements', async () => {
  const source = userscript.match(/async function checkInstance\(\) \{[\s\S]*?\n  \}/)[0]
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  for (const fields of [{ v: 1, issuedAtMs: -1, expiresAtMs: 1784629815250 }, { v: 2, issuedAt: -1, expiresAt: 1784629815 }]) {
    const statement = new TextEncoder().encode(JSON.stringify({ ...fields, websiteOrigin: 'https://example.test' }))
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, statement))
    const context = {
      TextDecoder, INSTANCE_KEYS: [], location: { origin: 'https://example.test' },
      load: async path => path.endsWith('.json') ? statement : new TextEncoder().encode(Buffer.from(signature).toString('base64')),
      bytes: value => Buffer.from(value, 'base64'),
      signedBy: async (_, message, signed) => crypto.subtle.verify('Ed25519', pair.publicKey, signed, message),
      Date: { now: () => 1784629815000 },
    }
    assert.equal((await runInNewContext(`(${source})()`, context)).ok, true)
    context.Date.now = () => 1784629816000
    assert.equal((await runInNewContext(`(${source})()`, context)).ok, false)
  }
})

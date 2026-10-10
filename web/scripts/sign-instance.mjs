import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'

export function instanceStatement(apiOrigin, websiteOrigin, issuedAtMs = Date.now(), validDays = 400) {
  for (const origin of [apiOrigin, websiteOrigin]) {
    const url = new URL(origin)
    if (url.protocol !== 'https:' || url.origin !== origin) throw new Error(`${origin} must be an https origin without a path`)
  }
  if (!Number.isInteger(validDays) || validDays < 1 || validDays > 800) throw new Error('validDays must be 1 to 800')
  return JSON.stringify({ v: 1, apiOrigin, websiteOrigin, issuedAtMs, expiresAtMs: issuedAtMs + validDays * 86400000 })
}

export function signInstance(statement, privateKeyPem) {
  return sign(null, Buffer.from(statement), createPrivateKey(privateKeyPem)).toString('base64')
}

export function verifyInstance(statement, signature, publicKeyPem) {
  return verify(null, Buffer.from(statement), createPublicKey(publicKeyPem), Buffer.from(signature, 'base64'))
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const [keyPath, apiOrigin, websiteOrigin, validDays = '400'] = process.argv.slice(2)
  if (!keyPath || !apiOrigin || !websiteOrigin) {
    console.error('usage: node scripts/sign-instance.mjs <private-key.pem> <api-origin> <website-origin> [valid-days]')
    process.exit(2)
  }
  const statement = instanceStatement(apiOrigin, websiteOrigin, Date.now(), Number(validDays))
  console.log(`REMOTESYNC_INSTANCE_STATEMENT='${statement}'`)
  console.log(`REMOTESYNC_INSTANCE_SIGNATURE=${signInstance(statement, await readFile(keyPath, 'utf8'))}`)
}

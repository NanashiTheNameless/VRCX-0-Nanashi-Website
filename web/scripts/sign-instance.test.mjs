import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import test from 'node:test'

import { instanceStatement, signInstance, verifyInstance } from './sign-instance.mjs'

const pem = key => key.export({ type: key.type === 'private' ? 'pkcs8' : 'spki', format: 'pem' })

test('an instance statement verifies only with the signing key and unchanged origins', () => {
  const official = generateKeyPairSync('ed25519')
  const other = generateKeyPairSync('ed25519')
  const statement = instanceStatement('https://api.example.com', 'https://www.example.com')
  const signature = signInstance(statement, pem(official.privateKey))
  assert.equal(verifyInstance(statement, signature, pem(official.publicKey)), true)
  assert.equal(verifyInstance(statement, signature, pem(other.publicKey)), false)
  assert.equal(verifyInstance(statement.replace('www.example.com', 'www.example.org'), signature, pem(official.publicKey)), false)
})

test('origins with a path or plain http are refused', () => {
  assert.throws(() => instanceStatement('http://api.example.com', 'https://www.example.com'))
  assert.throws(() => instanceStatement('https://api.example.com/', 'https://www.example.com'))
  assert.throws(() => instanceStatement('https://api.example.com', 'https://www.example.com/site'))
})

test('new statements carry signed seconds while old signed bytes remain verifiable', () => {
  const pair = generateKeyPairSync('ed25519')
  const statement = instanceStatement('https://api.example.com', 'https://www.example.com', -1, 1)
  assert.deepEqual(JSON.parse(statement), { v: 2, apiOrigin: 'https://api.example.com', websiteOrigin: 'https://www.example.com', issuedAt: -1, expiresAt: 86399 })
  const old = '{"v":1,"issuedAtMs":-1,"expiresAtMs":1784629815250}'
  const signature = signInstance(old, pem(pair.privateKey))
  assert.equal(verifyInstance(old, signature, pem(pair.publicKey)), true)
  assert.equal(verifyInstance(JSON.stringify(JSON.parse(statement)), signature, pem(pair.publicKey)), false)
})

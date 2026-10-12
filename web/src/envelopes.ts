import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { argon2id } from 'hash-wasm'

export type Envelope = {
  v: number
  envelopeId: string
  label: string
  createdAtMs: number
  lock: { kind: 'passphrase'; cost: { mKib: number; t: number; p: number }; salt: string; generated: boolean }
  nonce: string
  ciphertext: string
}

const encoder = new TextEncoder()
const cost = { mKib: 262144, t: 3, p: 1 }
const b64url = (bytes: Uint8Array) => btoa(Array.from(bytes, b => String.fromCharCode(b)).join('')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
const unb64url = (text: string) => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0))

function base32(bytes: Uint8Array) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  let result = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31]
  return result
}

export function generatePassphrase() {
  const chars = base32(randomBytes(17)).slice(0, 26)
  return chars.match(/.{1,5}/g)!.join('-')
}

function parseSecret(input: string) {
  const compact = input.trim().replace(/\s/g, '')
  if (/^[0-9a-fA-F]{64}$/.test(compact)) return Uint8Array.from(compact.match(/../g)!, pair => Number.parseInt(pair, 16))
  if (!compact.slice(0, 5).toLowerCase().startsWith('rss1-')) throw new Error('Enter a 64-character hexadecimal sync key or an rss1 recovery string.')
  const text = compact.slice(5).replaceAll('-', '').toUpperCase()
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const decoded: number[] = []
  for (const char of text) {
    const digit = alphabet.indexOf(char)
    if (digit < 0) throw new Error('The recovery string contains an invalid character.')
    value = (value << 5) | digit
    bits += 5
    if (bits >= 8) {
      bits -= 8
      decoded.push((value >>> bits) & 255)
    }
  }
  if (decoded.length !== 36 || (bits && (value & ((1 << bits) - 1)) !== 0)) throw new Error('The recovery string has an invalid length.')
  let crc = 0xffffffff
  for (const byte of decoded.slice(0, 32)) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0)
  }
  crc = (crc ^ 0xffffffff) >>> 0
  const expected = [(crc >>> 24) & 255, (crc >>> 16) & 255, (crc >>> 8) & 255, crc & 255]
  if (expected.some((byte, index) => decoded[index + 32] !== byte)) throw new Error('The recovery string checksum does not match.')
  return Uint8Array.from(decoded.slice(0, 32))
}

export async function generateWordPassphrase(count = 7) {
  const { EFF_WORDS } = await import('./effWords')
  const limit = Math.floor(65536 / EFF_WORDS.length) * EFF_WORDS.length
  const words: string[] = []
  while (words.length < count) {
    const [value] = crypto.getRandomValues(new Uint16Array(1))
    if (value < limit) words.push(EFF_WORDS[value % EFF_WORDS.length])
  }
  return words.join(' ')
}

export function normalizeSyncKey(input: string) { return Array.from(parseSecret(input), byte => byte.toString(16).padStart(2, '0')).join('') }

function aad(accountId: string, envelopeId: string) {
  return encoder.encode(`remotesync/v1/envelope\0${accountId}\0${envelopeId}\0passphrase\0`)
}

async function kek(passphrase: string, salt: Uint8Array, params: { mKib: number; t: number; p: number }, generated = true) {
  if (params.mKib < cost.mKib || params.t < cost.t || params.p < cost.p || params.mKib > 4 * 1024 * 1024 || params.t > 64 || params.p > 16) {
    throw new Error('This envelope uses unsafe or unsupported Argon2 parameters.')
  }
  const input = generated ? passphrase.replace(/[\s-]/g, '').toUpperCase() : passphrase
  const stretched = await argon2id({ password: encoder.encode(input), salt, iterations: params.t, parallelism: params.p, memorySize: params.mKib, hashLength: 32, outputType: 'binary' })
  return deriveKek(stretched)
}

async function deriveKek(input: Uint8Array) {
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(input).buffer, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: encoder.encode('remotesync/v1/envelope-kek') }, key, 256))
}

export async function createPassphraseEnvelope(accountId: string, syncKeyHex: string, label: string, passphrase: string, generated = true): Promise<Envelope> {
  if (!label.trim() || label.length > 64) throw new Error('Give this key envelope a label of 1 to 64 characters.')
  const secret = parseSecret(syncKeyHex)
  const salt = randomBytes(16)
  const nonce = randomBytes(24)
  const id = b64url(randomBytes(16))
  const key = await kek(passphrase, salt, cost, generated)
  const ciphertext = xchacha20poly1305(key, nonce, aad(accountId, id)).encrypt(secret)
  return { v: 1, envelopeId: id, label: label.trim(), createdAtMs: Date.now(), lock: { kind: 'passphrase', cost, salt: b64url(salt), generated }, nonce: b64url(nonce), ciphertext: b64url(ciphertext) }
}

export async function openPassphraseEnvelope(accountId: string, envelope: Envelope, passphrase: string) {
  if (envelope.v !== 1 || envelope.lock.kind !== 'passphrase') throw new Error('This envelope type is not supported by the website yet.')
  const key = await kek(passphrase, unb64url(envelope.lock.salt), envelope.lock.cost, envelope.lock.generated)
  const secret = xchacha20poly1305(key, unb64url(envelope.nonce), aad(accountId, envelope.envelopeId)).decrypt(unb64url(envelope.ciphertext))
  if (secret.byteLength !== 32) throw new Error('The decrypted sync key has an invalid length.')
  return Array.from(secret, b => b.toString(16).padStart(2, '0')).join('')
}

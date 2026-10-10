import assert from 'node:assert/strict'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { validateCollectorInput } from './collector-input.mjs'

const appVersion = '1.2.3'
const appCommit = '0123456789abcdef0123456789abcdef01234567'

async function fixture() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'collector-input-'))
  const binaryPath = path.join(dir, 'vrcx-0-nanashi-headless-linux-amd64')
  const elf = Buffer.alloc(64)
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])
  elf.writeUInt16LE(2, 16)
  elf.writeUInt16LE(62, 18)
  await writeFile(binaryPath, elf)
  await chmod(binaryPath, 0o755)
  return { dir, binaryPath }
}

test('rejects missing executable and metadata inputs', async () => {
  await assert.rejects(
    validateCollectorInput({ binaryPath: '', appVersion: '', appCommit: '', compatibilityVersion: '', compatibilityCommit: '', targetArch: '' }),
    /binaryPath is required/,
  )
})

test('rejects mismatched app version', async (t) => {
  const input = await fixture()
  t.after(() => rm(input.dir, { recursive: true, force: true }))
  await assert.rejects(validateCollectorInput({
    ...input, appVersion, appCommit, compatibilityVersion: '1.2.4', compatibilityCommit: appCommit, targetArch: 'amd64',
  }), /version does not match/)
})

test('rejects mismatched full app commit', async (t) => {
  const input = await fixture()
  t.after(() => rm(input.dir, { recursive: true, force: true }))
  await assert.rejects(validateCollectorInput({
    ...input, appVersion, appCommit, compatibilityVersion: appVersion,
    compatibilityCommit: 'fedcba9876543210fedcba9876543210fedcba98', targetArch: 'amd64',
  }), /commit does not match/)
})

test('accepts a matching Linux amd64 ELF fixture binary', async (t) => {
  const input = await fixture()
  t.after(() => rm(input.dir, { recursive: true, force: true }))
  const metadata = await validateCollectorInput({
    ...input, appVersion, appCommit, compatibilityVersion: appVersion,
    compatibilityCommit: appCommit, targetArch: 'amd64',
  })
  assert.equal(metadata.architecture, 'linux/amd64')
  assert.equal(metadata.format, 'ELF64 x86-64')
  assert.equal(metadata.appCommit, appCommit)
})

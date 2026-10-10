import { readFile, stat, writeFile } from 'node:fs/promises'

const SHA1 = /^[0-9a-f]{40}$/i

export async function validateCollectorInput({
  binaryPath,
  appVersion,
  appCommit,
  compatibilityVersion,
  compatibilityCommit,
  targetArch,
}) {
  const required = { binaryPath, appVersion, appCommit, compatibilityVersion, compatibilityCommit, targetArch }
  for (const [name, value] of Object.entries(required)) {
    if (!value) throw new Error(`${name} is required`)
  }
  if (targetArch !== 'amd64') throw new Error(`unsupported collector architecture: ${targetArch}; expected amd64`)
  if (!SHA1.test(appCommit)) throw new Error('appCommit must be a full 40-character commit')
  if (!SHA1.test(compatibilityCommit)) throw new Error('compatibilityCommit must be a full 40-character commit')
  if (appVersion !== compatibilityVersion) throw new Error('collector app version does not match the configured compatibility version')
  if (appCommit.toLowerCase() !== compatibilityCommit.toLowerCase()) throw new Error('collector app commit does not match the configured compatibility commit')

  const [{ mode }, bytes] = await Promise.all([stat(binaryPath), readFile(binaryPath)])
  if (!mode || (mode & 0o111) === 0) throw new Error('collector binary must be executable')
  if (bytes.length < 20 || bytes.subarray(0, 4).toString('hex') !== '7f454c46') throw new Error('collector binary must be an ELF executable')
  if (bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== 62) {
    throw new Error('collector binary must be a little-endian ELF64 Linux x86-64 executable')
  }

  return {
    appVersion,
    appCommit: appCommit.toLowerCase(),
    compatibilityVersion,
    compatibilityCommit: compatibilityCommit.toLowerCase(),
    architecture: 'linux/amd64',
    format: 'ELF64 x86-64',
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const [binaryPath, appVersion, appCommit, compatibilityVersion, compatibilityCommit, targetArch, metadataPath] = process.argv.slice(2)
  try {
    const metadata = await validateCollectorInput({ binaryPath, appVersion, appCommit, compatibilityVersion, compatibilityCommit, targetArch })
    await writeFile(metadataPath, `${JSON.stringify(metadata)}\n`, { flag: 'wx' })
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}

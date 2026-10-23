type Entry = { key: string; accountId: string; value: unknown; updatedAt: number }
const DB_NAME = 'remotesync-history-cache-v1'
const STORE = 'encrypted'
const MAX_ENTRIES = 400

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2)
    request.onupgradeneeded = (event) => {
      if (event.oldVersion === 0) request.result.createObjectStore(STORE, { keyPath: 'key' }).createIndex('accountId', 'accountId')
      else {
        const cursor = request.transaction!.objectStore(STORE).openCursor()
        cursor.onsuccess = () => {
          const current = cursor.result
          if (!current) return
          const entry = current.value as Entry
          current.update({ ...entry, updatedAt: Math.floor(entry.updatedAt / 1000), value: entry.key.endsWith(':vaults') ? convertCachedVaults(entry.value) : entry.value })
          current.continue()
        }
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

export async function readHistoryCache<T>(accountId: string, key: string): Promise<T | undefined> {
  try {
    const db = await openDb()
    const value = await new Promise<Entry | undefined>((resolve, reject) => {
      const request = db.transaction(STORE).objectStore(STORE).get(`${accountId}:${key}`)
      request.onsuccess = () => resolve(request.result as Entry | undefined)
      request.onerror = () => reject(request.error)
    })
    db.close()
    return value?.value as T | undefined
  } catch { return undefined }
}

export async function writeHistoryCache(accountId: string, key: string, value: unknown): Promise<void> {
  try {
    const db = await openDb()
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).put({ key: `${accountId}:${key}`, accountId, value, updatedAt: Math.floor(Date.now() / 1000) } satisfies Entry)
    await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error) })
    const entries = await new Promise<Entry[]>((resolve, reject) => {
      const request = db.transaction(STORE).objectStore(STORE).index('accountId').getAll(accountId)
      request.onsuccess = () => resolve(request.result as Entry[])
      request.onerror = () => reject(request.error)
    })
    if (entries.length > MAX_ENTRIES) {
      const prune = db.transaction(STORE, 'readwrite')
      for (const entry of entries.sort((a, b) => a.updatedAt - b.updatedAt).slice(0, entries.length - MAX_ENTRIES)) prune.objectStore(STORE).delete(entry.key)
    }
    db.close()
  } catch { /* Caching is optional; the network result remains usable. */ }
}

export async function clearHistoryCache(accountId: string): Promise<void> {
  try {
    const db = await openDb()
    const tx = db.transaction(STORE, 'readwrite')
    const request = tx.objectStore(STORE).index('accountId').openKeyCursor(accountId)
    request.onsuccess = () => { const cursor = request.result; if (cursor) { tx.objectStore(STORE).delete(cursor.primaryKey); cursor.continue() } }
    await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error) })
    db.close()
  } catch { /* A missing cache needs no cleanup. */ }
}

function convertCachedVaults(value: unknown): unknown {
  if (!Array.isArray(value)) return value
  return value.map(vault => {
    if (!vault || typeof vault !== 'object' || typeof vault.createdAtMs !== 'number') return vault
    const { createdAtMs, ...fields } = vault
    return { ...fields, createdAt: Math.floor(createdAtMs / 1000) }
  })
}

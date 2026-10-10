type Entry = { key: string; accountId: string; value: unknown; updatedAt: number }
const DB_NAME = 'remotesync-history-cache-v1'
const STORE = 'encrypted'
const MAX_ENTRIES = 400

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'key' }).createIndex('accountId', 'accountId')
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
    tx.objectStore(STORE).put({ key: `${accountId}:${key}`, accountId, value, updatedAt: Date.now() } satisfies Entry)
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

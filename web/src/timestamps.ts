export function epochSeconds(value: unknown): number | null {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < -9223372036854775808 || value >= 9223372036854775808) return null
    const integer = Math.floor(value)
    return Math.abs(integer) >= 100_000_000_000 ? Math.floor(integer / 1000) : integer
  }
  if (typeof value !== 'string' || !value.trim()) return null
  const text = value.trim()
  if (/^[+-]?\d+$/.test(text)) return epochSeconds(Number(text))
  const utcText = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(text) ? `${text.replace(' ', 'T')}Z` : text
  const milliseconds = Date.parse(utcText)
  return Number.isFinite(milliseconds) ? Math.floor(milliseconds / 1000) : null
}

export function rowTime(value: unknown, fallback: number): number {
  if (!value || typeof value !== 'object') return fallback
  const row = value as Record<string, unknown>
  for (const key of ['created_at', 'createdAt', 'occurred_at', 'occurredAt', 'timestamp', 'date', 'updated_at', 'updatedAt', 'checked_at', 'edited_at', 'last_fetched_at', 'started_at', 'ended_at', 'start_at', 'end_at', 'added_at', 'fetched_at', 'first_viewed_at', 'last_viewed_at', 'expires_at']) {
    const seconds = epochSeconds(row[key])
    if (seconds !== null) return seconds
  }
  for (const key of ['created_at_ms', 'createdAtMs', 'timestamp_ms', 'timestampMs', 'occurred_at_ms', 'occurredAtMs', 'time_ms', 'timeMs', 'date_ms', 'dateMs', 'updated_at_ms', 'updatedAtMs', 'checked_at_ms', 'edited_at_ms', 'last_fetched_at_ms', 'started_at_ms', 'ended_at_ms', 'start_at_ms', 'end_at_ms']) {
    const candidate = row[key]
    if ((typeof candidate === 'number' || typeof candidate === 'string') && String(candidate).trim() && Number.isFinite(Number(candidate))) return Math.floor(Number(candidate) / 1000)
  }
  return fallback
}

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { epochSeconds, rowTime } from '../src/timestamps.ts'

test('normalizes seconds, milliseconds, ISO offsets and SQLite UTC timestamps', () => {
  for (const value of [1784629815, 1784629815250, '1784629815250', '2026-07-21T10:30:15.250Z', '2026-07-21T05:30:15-05:00', '2026-07-21 10:30:15.250']) assert.equal(epochSeconds(value), 1784629815)
  assert.equal(epochSeconds(-100000000001), -100000001)
  assert.equal(epochSeconds(99999999999), 99999999999)
  assert.equal(epochSeconds(100000000000), 100000000)
  assert.equal(epochSeconds('1969-12-31T23:59:59Z'), -1)
  assert.equal(epochSeconds('invalid'), null)
  assert.equal(epochSeconds('1969-12-31T23:59:59.999Z'), -1)
  assert.equal(epochSeconds('1969-12-31 23:59:59.999'), -1)
  assert.equal(epochSeconds(-99999999999), -99999999999)
  assert.equal(epochSeconds(-100000000000), -100000000)
})

test('uses actual row dates and keeps zero and signed legacy milliseconds', () => {
  assert.equal(rowTime({ created_at: 1784629815, time: 30 }, 42), 1784629815)
  assert.equal(rowTime({ created_at: '2026-07-21T10:30:15.250Z' }, 42), 1784629815)
  assert.equal(rowTime({ created_at_ms: -1 }, 42), -1)
  assert.equal(rowTime({ createdAtMs: 1000 }, 42), 1)
  assert.equal(rowTime({ created_at: 0 }, 42), 0)
  assert.equal(rowTime({ time: 30000 }, 42), 42)
})

test('history date extraction preserves distinct same-second events and repeat import identity', () => {
  const fixtures = JSON.parse(readFileSync(new URL('../../crates/protocol/tests/fixtures/legacy-events.json', import.meta.url)))
  for (const item of fixtures) {
    const expected = item.legacy.created_at.endsWith('.000Z') ? '' : createHash('sha256').update(item.legacy.created_at).digest('hex')
    assert.equal(item.imported.event_discriminator, expected)
  }
  for (const form of ['legacy', 'imported']) {
    const rows = fixtures.map(item => item[form])
    const original = JSON.stringify(rows)
    for (let attempt = 0; attempt < 2; attempt++) {
      const imported = JSON.parse(original)
      assert.deepEqual(imported.map(row => rowTime(row, 42)), [1784629815, 1784629815, 1784629815])
      if (form === 'imported') assert.notEqual(imported[0].event_discriminator, imported[1].event_discriminator)
      else assert.notEqual(imported[0].created_at, imported[1].created_at)
      assert.equal(JSON.stringify(imported), original)
    }
  }
})

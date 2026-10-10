import assert from 'node:assert/strict'
import test from 'node:test'

import { EFF_WORDS } from '../src/effWords.ts'

test('the bundled word list is the full EFF large list', () => {
  assert.equal(EFF_WORDS.length, 7776)
  assert.equal(new Set(EFF_WORDS).size, 7776)
  assert.equal(EFF_WORDS[0], 'abacus')
  assert.equal(EFF_WORDS.at(-1), 'zoom')
  assert.ok(EFF_WORDS.every(word => /^[a-z]+(-[a-z]+)*$/.test(word)))
})

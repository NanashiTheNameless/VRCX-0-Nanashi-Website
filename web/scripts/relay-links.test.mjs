import assert from 'node:assert/strict'
import test from 'node:test'

import { appLink, parsePreview, parseRelayLocation, vrchatLink } from '../src/relayLinks.ts'

const world = 'wrld_12345678-1234-1234-1234-1234567890ab'
const avatar = 'avtr_12345678-1234-1234-1234-1234567890ab'

test('world and avatar links take the id from the path only', () => {
  const target = parseRelayLocation(`/open/world/${world}`, '', '#n=Home&a=Someone&i=https%3A%2F%2Fapi.vrchat.cloud%2Fimage.png')
  assert.deepEqual(target, {
    kind: 'world',
    id: world,
    preview: { name: 'Home', author: 'Someone', imageUrl: 'https://api.vrchat.cloud/image.png' },
  })
  assert.equal(appLink(target), `vrcx-0-nanashi://world/open?id=${world}`)
  assert.equal(vrchatLink(target), `https://vrchat.com/home/world/${world}`)
  assert.equal(parseRelayLocation(`/open/avatar/${avatar}`, '', '').kind, 'avatar')
})

test('invalid ids and unknown routes are rejected', () => {
  assert.equal(parseRelayLocation(`/open/world/${avatar}`, '', ''), null)
  assert.equal(parseRelayLocation('/open/world/wrld_nope', '', ''), null)
  assert.equal(parseRelayLocation(`/open/user/${world}`, '', ''), null)
  assert.equal(parseRelayLocation(`/open/world/${world}/extra`, '', ''), null)
  assert.equal(parseRelayLocation('/open/world/%E0%A4%A', '', ''), null)
})

test('preview images are limited to VRChat hosts over https and text is capped', () => {
  assert.equal(parsePreview('#i=https%3A%2F%2Fexample.com%2Fa.png').imageUrl, '')
  assert.equal(parsePreview('#i=http%3A%2F%2Fapi.vrchat.cloud%2Fa.png').imageUrl, '')
  assert.equal(parsePreview('#i=javascript%3Aalert(1)').imageUrl, '')
  assert.equal(parsePreview('#i=https%3A%2F%2Fassets.vrchat.com%2Fa.png').imageUrl, 'https://assets.vrchat.com/a.png')
  assert.equal(Array.from(parsePreview(`#n=${'x'.repeat(500)}`).name).length, 200)
})

test('instance links keep access tags and tokens in the deep link', () => {
  const instanceId = '12345~private(usr_12345678-1234-1234-1234-1234567890ab)~region(jp)'
  const search = `?${new URLSearchParams({ instanceId, shortName: 'abc+/=', launchToken: 'tok' })}`
  const target = parseRelayLocation(`/open/instance/${world}`, search, '')
  assert.deepEqual(target, { kind: 'instance', worldId: world, instanceId, shortName: 'abc+/=', launchToken: 'tok' })
  const link = new URL(appLink(target))
  assert.equal(link.protocol, 'vrcx-0-nanashi:')
  assert.equal(link.searchParams.get('id'), world)
  assert.equal(link.searchParams.get('instanceId'), instanceId)
  assert.equal(link.searchParams.get('shortName'), 'abc+/=')
  assert.equal(link.searchParams.get('launchToken'), 'tok')
  assert.equal(new URL(vrchatLink(target)).searchParams.get('launchToken'), null)
})

test('malformed instance links are rejected', () => {
  const path = `/open/instance/${world}`
  assert.equal(parseRelayLocation(path, '', ''), null)
  assert.equal(parseRelayLocation(path, '?instanceId=1&instanceId=2', ''), null)
  assert.equal(parseRelayLocation(path, '?instanceId=1%3A2', ''), null)
  assert.equal(parseRelayLocation(path, '?instanceId=1&shortName=a%20b', ''), null)
  assert.equal(parseRelayLocation(path, '?instanceId=1&launchToken=a%00b', ''), null)
})

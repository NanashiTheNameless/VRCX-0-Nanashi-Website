import { test } from 'node:test'
import assert from 'node:assert/strict'
import { emojiLabel, parseFollowLink, parsePartyLink, partyAppLink, userAppLink } from '../src/followLinks.ts'

const A = 'usr_11111111-1111-1111-1111-111111111111'
const B = 'usr_22222222-2222-2222-2222-222222222222'

test('reads a follow link and drops unknown requirements and reserved emojis', () => {
  assert.deepEqual(parseFollowLink(`#u=${A}&n=Nanashi&r=friend,adult,bogus,friend&e=default_fire`), {
    userId: A, name: 'Nanashi', requirements: ['friend', 'adult'], emoji: 'default_fire',
  })
  assert.equal(parseFollowLink(`#u=${A}&e=default_stop`).emoji, '')
  assert.equal(parseFollowLink('#u=usr_bad'), null)
  assert.equal(parseFollowLink(`#u=${A}&u=${B}`), null)
  assert.equal(parseFollowLink(`#u=${A}&n=a%01b`).name, '')
  assert.equal(userAppLink(A), `vrcx-0-nanashi://user/open?id=${A}`)
})

test('reads a party link and builds the matching app link', () => {
  const party = parsePartyLink(`#p=abc123def&n=Crew&e=default_go&f=leader&l=${A}&m=${A}:member,${B}:guest`)
  assert.deepEqual(party, {
    partyId: 'abc123def', name: 'Crew', emoji: 'default_go', followMode: 'leader', leaderUserId: A,
    members: [{ userId: A, role: 'member' }, { userId: B, role: 'guest' }],
  })
  const link = new URL(partyAppLink(party))
  assert.equal(link.protocol, 'vrcx-0-nanashi:')
  assert.deepEqual(link.searchParams.getAll('m'), [`${A}:member`, `${B}:guest`])
  assert.equal(link.searchParams.get('leader'), A)
})

test('rejects malformed party links', () => {
  for (const hash of [
    `#p=abc&e=default_go&f=anyone&m=${A}:member`,
    `#p=abc123def&e=default_stop&f=anyone&m=${A}:member`,
    `#p=abc123def&e=default_go&f=other&m=${A}:member`,
    `#p=abc123def&e=default_go&f=anyone&m=${A}:owner`,
    `#p=abc123def&e=default_go&f=anyone&m=${A}:member,${A}:guest`,
    `#p=abc123def&e=default_go&f=leader&l=${B}&m=${A}:member`,
    `#p=abc123def&e=default_go&f=anyone`,
  ]) assert.equal(parsePartyLink(hash), null, hash)
})

test('labels emojis for people', () => {
  assert.equal(emojiLabel('default_music_note'), 'Music Note')
})

// Follow and party links carry everything in the URL fragment, which the
// browser never sends to this website. What they show is informational: the
// app enforces every rule against VRChat itself.

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
const USER_ID = new RegExp(`^usr_${UUID}$`, 'i')
const EMOJI_ID = /^default_[a-z_]{1,40}$/
const PARTY_ID = /^[A-Za-z0-9-]{6,40}$/
const NAME_LIMIT = 60
const MAX_MEMBERS = 32
const APP_SCHEME = 'vrcx-0-nanashi'
const STOP_EMOJI = 'default_stop'

export type FollowRequirement = 'friend' | 'verified' | 'adult' | 'group'
export type FollowLink = { userId: string; name: string; requirements: FollowRequirement[]; emoji: string }
export type PartyMember = { userId: string; role: 'member' | 'guest' }
export type PartyLink = {
  partyId: string
  name: string
  emoji: string
  followMode: 'leader' | 'anyone'
  leaderUserId: string
  members: PartyMember[]
}

const REQUIREMENTS: FollowRequirement[] = ['friend', 'verified', 'adult', 'group']

const hasControl = (value: string) =>
  Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code < 32 || (code >= 127 && code <= 159)
  })

function name(value: string | null) {
  const text = Array.from((value ?? '').trim()).slice(0, NAME_LIMIT).join('')
  return hasControl(text) ? '' : text
}

function single(params: URLSearchParams, key: string) {
  const values = params.getAll(key)
  return values.length > 1 ? null : values[0] ?? ''
}

function consentEmoji(value: string) {
  return EMOJI_ID.test(value) && value !== STOP_EMOJI ? value : ''
}

export function emojiLabel(emojiId: string) {
  return emojiId
    .replace(/^default_/, '')
    .split('_')
    .filter(Boolean)
    .map(word => word[0].toUpperCase() + word.slice(1))
    .join(' ')
}

export function parseFollowLink(hash: string): FollowLink | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  const userId = single(params, 'u')
  const requirementText = single(params, 'r')
  const emoji = single(params, 'e')
  if (!userId || !USER_ID.test(userId) || requirementText === null || emoji === null) return null
  const requirements = requirementText
    .split(',')
    .filter((value): value is FollowRequirement => REQUIREMENTS.includes(value as FollowRequirement))
  return { userId, name: name(single(params, 'n')), requirements: [...new Set(requirements)], emoji: consentEmoji(emoji) }
}

export function parsePartyLink(hash: string): PartyLink | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''))
  const partyId = single(params, 'p')
  const emoji = single(params, 'e')
  const mode = single(params, 'f')
  const leader = single(params, 'l')
  const memberText = single(params, 'm')
  if (!partyId || !PARTY_ID.test(partyId) || !emoji || !consentEmoji(emoji)) return null
  if ((mode !== 'leader' && mode !== 'anyone') || leader === null || !memberText) return null
  const members: PartyMember[] = []
  for (const entry of memberText.split(',')) {
    const [userId, role, extra] = entry.split(':')
    if (extra !== undefined || !USER_ID.test(userId ?? '') || (role !== 'member' && role !== 'guest')) return null
    if (members.some(member => member.userId === userId) || members.length >= MAX_MEMBERS) return null
    members.push({ userId, role })
  }
  if (mode === 'leader' && !members.some(member => member.userId === leader)) return null
  return {
    partyId,
    name: name(single(params, 'n')),
    emoji,
    followMode: mode,
    leaderUserId: mode === 'leader' ? leader : '',
    members,
  }
}

export function userAppLink(userId: string) {
  return `${APP_SCHEME}://user/open?id=${encodeURIComponent(userId)}`
}

export function userVrchatLink(userId: string) {
  return `https://vrchat.com/home/user/${encodeURIComponent(userId)}`
}

export function partyAppLink(party: PartyLink) {
  const params = new URLSearchParams({ id: party.partyId })
  if (party.name) params.set('name', party.name)
  params.set('emoji', party.emoji)
  params.set('mode', party.followMode)
  if (party.leaderUserId) params.set('leader', party.leaderUserId)
  for (const member of party.members) params.append('m', `${member.userId}:${member.role}`)
  return `${APP_SCHEME}://party/join?${params}`
}

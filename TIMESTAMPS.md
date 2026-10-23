# Timestamp conversion inventory

Surveyed against HEAD and the existing partial conversion on 2026-10-23.
All new absolute dates are signed i64 Unix seconds in UTC. Display uses the
browser timezone. Explicit legacy millisecond fields always divide by 1000
with floor rounding, including values near 1970. Bare integers use milliseconds
only when their absolute magnitude is at least 100000000000.

## Protocol

| Object | Legacy fields (milliseconds) | New seconds fields | Versions |
| --- | --- | --- | --- |
| Signed chunk header | createdAtMs | createdAt | 1 -> 2 |
| Signed chunk coverage | startMs, endMs | start, end | chunk 1 -> 2 |
| Signed manifest signer | addedAtMs, expiresAtMs | addedAt, expiresAt | 1-3 -> 4 |
| Signed live snapshot | createdAtMs | createdAt | 1 -> 2 |
| Signed live friend | lastSeenAtMs | lastSeenAt | live 1 -> 2 |
| Key envelope metadata | createdAtMs | createdAt | 1 -> 2 |
| Blob listing | lastModifiedMs | lastModified | API transition |
| Signed instance statement (JavaScript) | issuedAtMs, expiresAtMs | issuedAt, expiresAt | 1 -> 2 |

Envelope timestamps are metadata outside the authenticated encryption AAD.
Chunk, manifest and live verification must use the original signed CBOR byte
strings, never a serialization of the converted structs. Cryptographic domain
and key derivation strings retain their existing v1 values.

## Server databases

Every field below was INTEGER milliseconds in schema 1. Schema 2 renames each
column by dropping `_ms` and converts it once, preserving NULL and every row.
Stored envelope, collection and signed manifest bodies remain untouched.
Registry migration runs when the registry opens; each account database migrates
when opened. Each migration and its schema version update commit in one
transaction. Earlier servers reject schema 2, so reverting the executable alone
does not downgrade an upgraded database.

| Database | Table | Date columns in schema 1 |
| --- | --- | --- |
| Account | vaults | created_at_ms |
| Account | envelopes | created_at_ms |
| Account | collections | updated_at_ms |
| Registry | accounts | email_verified_at_ms, created_at_ms |
| Registry | recovery_codes | used_at_ms |
| Registry | tokens | created_at_ms, last_used_ms, expires_at_ms, revoked_at_ms, recent_auth_until_ms, recent_totp_until_ms |
| Registry | client_ips | first_seen_ms, last_seen_ms |
| Registry | device_pairings | expires_at_ms, next_poll_ms |
| Registry | transfers | expires_at_ms |
| Registry | auth_tokens | expires_at_ms |
| Registry | email_codes | expires_at_ms |
| Registry | collection_index | updated_at_ms |
| Registry | blob_deletions | next_attempt_ms |
| Registry | audit_log | at_ms |

`tokens.idle_timeout_ms` is a duration and stays milliseconds.
`device_pairings.interval_s` is a duration and stays seconds.
`totp_last_step` is a counter, not an absolute timestamp.
Collector live_seq is also a counter, seeded from the millisecond clock to
retain its existing ordering and uniqueness properties.

## API JSON

The user selected an immediate client switch. New routes are `/v2`, `/web/v2`
and `/public/v2`. Old desktop routes return an explicit upgrade-required error.

| Payload | Legacy millisecond names | Seconds names |
| --- | --- | --- |
| Collector capabilities | keysValidSinceMs | keysValidSince |
| Client IP and client info | firstSeenMs, lastSeenMs, revokedAtMs | firstSeen, lastSeen, revokedAt |
| Vault info | createdAtMs | createdAt |
| Collector status | sinceMs, lastChunkAtMs | since, lastChunkAt |
| Web account/admin account | createdAtMs | createdAt |
| Web audit | atMs | at |
| Web pairing | expiresAtMs | expiresAt |
| Web authentication | recentAuthUntilMs, recentTotpUntilMs | recentAuthUntil, recentTotpUntil |
| Web envelope summary | createdAtMs | createdAt |

Collection snapshots already use `updated_at` seconds. Old collection JSON
must remain readable. `expiresIn`, `interval`, live age and retry-after are
durations in seconds. Token idle timeout remains milliseconds.
ALTCHA challenge expires_at already uses seconds.

## Collector

Key validity, session start, last chunk, chunk creation, live creation and friend
last seen become seconds. Unlock `expiresAt` accepts legacy integer milliseconds,
seconds and date text. Child row dates may contain legacy ISO text or new
seconds. Before sealing a new chunk, history::normalize_row converts recognized
date fields and preserves all other values. For game-log rows missing
event_discriminator, it derives the desktop identity from the original date
before conversion; supplied discriminators remain unchanged.
Polling, flush, live refresh, update, network and process timeout durations retain
their existing units.

## Web UI

| Consumer | Dates |
| --- | --- |
| dashboard.tsx | account creation, vault creation, envelope creation, client first/last seen and revocation, audit time, signer addition/expiry |
| account.tsx | client first/last seen and revocation, pairing expiry |
| collector.tsx | key validity, signer expiry, collector since and last chunk, unlock expiry |
| envelopes.ts | envelope creation |
| publicPages.tsx | collection updated_at, already seconds |
| history.tsx | chunk header creation, live creation, decrypted row dates |
| timestamps.ts | created_at/createdAt, occurred_at/occurredAt, timestamp, date, updated_at/updatedAt, checked_at, edited_at, last_fetched_at, started_at and legacy millisecond aliases |
| reauth.tsx | in-memory verification deadline |
| historyCache.ts | cache entry updatedAt; cached vault createdAtMs migrates to createdAt |
| userscript/remotesync-verify.user.js | signed instance expiry; verifies original statement bytes for versions 1 and 2 |

Numeric dates multiply by 1000 when constructing Date. Date.now(), performance
timers, transfer waiting time, cache TTLs and setTimeout/setInterval are durations
or browser clock interfaces and retain their browser units. Local date filter
boundaries convert browser milliseconds to seconds before comparing row dates.

## Collision preservation

History rows must retain event_discriminator as an opaque string. Distinct legacy
events in one second must remain distinct. The desktop import identity hashes
the exact original timestamp with SHA-256, except canonical zero-fraction UTC
millisecond text uses the empty string. Numeric seconds and whole numeric
milliseconds also use the empty string; fractional legacy numeric milliseconds
hash their decimal representation. An explicitly supplied discriminator is never
replaced. Importing the same row repeatedly must retain the same identity.

The server stores encrypted chunk bodies without importing or deduplicating rows.
The history viewer displays each row and preserves its raw payload. Desktop
database import and export are implemented in the desktop repository and are
outside this checkout's writable scope. Shared fixtures test collector row
normalization, repeated normalization, encrypted chunk round-trips, JSON
import/export, and history date extraction for both original and imported rows.

## Validation

- cargo test --workspace --locked: 149 tests passed.
- cargo clippy --workspace --all-targets --locked -- -D warnings: passed.
- npm test in web: 21 tests passed.
- npm run build in web on Node 26: passed, including release WASM compilation.
- Collection date and cursor regression: passed after the final audit fix.
- Encrypted old-schema copies cover every column, NULL, positive and negative
  dates, i64::MIN, repeat migration, foreign keys, integrity and wrong-key access.

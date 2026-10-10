use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use vrcx_0_nanashi_website_protocol::api::{ClientKind, Scope};
use vrcx_0_nanashi_website_protocol::ids::AccountId;

use super::{DbError, DbResult, migrate, open_encrypted};

const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email_verified_at_ms INTEGER,
    password_hash TEXT,
    state TEXT NOT NULL CHECK (state IN ('unverified', 'pending', 'active', 'suspended')),
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'owner')),
    quota_bytes INTEGER,
    max_vaults INTEGER NOT NULL DEFAULT 5,
    collector_allowed INTEGER NOT NULL DEFAULT 0,
    sync_allowed INTEGER NOT NULL DEFAULT 1,
    signup_message TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    wrapped_adk BLOB,
    usage_bytes INTEGER NOT NULL DEFAULT 0,
    twofa_method TEXT CHECK (twofa_method IN ('totp', 'email')),
    totp_secret_wrapped BLOB,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    totp_pending_wrapped BLOB,
    quota_warned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE recovery_codes (
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    code_hmac BLOB NOT NULL,
    used_at_ms INTEGER,
    PRIMARY KEY (account_id, code_hmac)
);

CREATE TABLE tokens (
    token_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('api', 'session')),
    client_kind TEXT NOT NULL,
    secret_hmac BLOB NOT NULL,
    scopes TEXT NOT NULL,
    label TEXT NOT NULL,
    client_version TEXT,
    created_at_ms INTEGER NOT NULL,
    last_used_ms INTEGER,
    expires_at_ms INTEGER,
    idle_timeout_ms INTEGER,
    revoked_at_ms INTEGER,
    revoked_by TEXT,
    recent_auth_until_ms INTEGER NOT NULL DEFAULT 0,
    recent_totp_until_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX tokens_account ON tokens (account_id);

CREATE TABLE client_ips (
    client_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    ip TEXT NOT NULL,
    city TEXT,
    region TEXT,
    country TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    PRIMARY KEY (client_id, ip)
);
CREATE INDEX client_ips_account ON client_ips (account_id);
CREATE INDEX client_ips_last_seen ON client_ips (last_seen_ms);

CREATE TABLE device_pairings (
    device_code_hmac BLOB PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    device_label TEXT NOT NULL,
    requested_scopes TEXT NOT NULL,
    approved_scopes TEXT,
    account_id TEXT REFERENCES accounts ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    expires_at_ms INTEGER NOT NULL,
    next_poll_ms INTEGER NOT NULL DEFAULT 0,
    interval_s INTEGER NOT NULL DEFAULT 5
);

CREATE TABLE transfers (
    transfer_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    epk BLOB NOT NULL,
    sealed BLOB,
    expires_at_ms INTEGER NOT NULL
);

CREATE TABLE auth_tokens (
    token_hmac BLOB PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    data TEXT
);
CREATE INDEX auth_tokens_account ON auth_tokens (account_id);

CREATE TABLE email_codes (
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    code_hmac BLOB NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, purpose)
);

CREATE TABLE collection_index (
    code TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts ON DELETE CASCADE,
    listed INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX collection_index_listed ON collection_index (listed, updated_at_ms);

CREATE TABLE blob_deletions (
    target TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('object', 'prefix')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_account TEXT,
    at_ms INTEGER NOT NULL
);
CREATE INDEX audit_log_target ON audit_log (target_account);
"#];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountState {
    Unverified,
    Pending,
    Active,
    Suspended,
}

impl AccountState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    fn parse(value: &str) -> DbResult<Self> {
        Ok(match value {
            "unverified" => Self::Unverified,
            "pending" => Self::Pending,
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            _ => return Err(DbError::Invalid("account state")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    User,
    Admin,
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(value: &str) -> DbResult<Self> {
        Ok(match value {
            "user" => Self::User,
            "admin" => Self::Admin,
            "owner" => Self::Owner,
            _ => return Err(DbError::Invalid("account role")),
        })
    }

    pub fn can_administer(self) -> bool {
        self >= Self::Admin
    }
}

#[derive(Clone, Debug)]
pub struct AccountRow {
    pub account_id: AccountId,
    pub email: String,
    pub state: AccountState,
    pub role: Role,
    pub quota_bytes: Option<u64>,
    pub max_vaults: u32,
    pub collector_allowed: bool,
    pub sync_allowed: bool,
    pub created_at_ms: i64,
    pub wrapped_adk: Option<Vec<u8>>,
    pub usage_bytes: u64,
    pub signup_message: String,
}

pub type CollectionIndexRow = (String, AccountId, String, Option<String>, i64);

impl AccountRow {
    pub fn is_owner(&self) -> bool {
        self.role == Role::Owner
    }

    pub fn effective_quota(&self) -> Option<u64> {
        if self.is_owner() {
            None
        } else {
            self.quota_bytes
        }
    }

    pub fn effective_max_vaults(&self) -> u32 {
        if self.is_owner() {
            u32::MAX
        } else {
            self.max_vaults
        }
    }

    pub fn effective_collector_allowed(&self) -> bool {
        self.sync_allowed && (self.is_owner() || self.collector_allowed)
    }
}

#[derive(Clone, Debug)]
pub struct TokenRow {
    pub token_id: String,
    pub account_id: AccountId,
    pub kind: String,
    pub client_kind: ClientKind,
    pub secret_hmac: Vec<u8>,
    pub scopes: Vec<Scope>,
    pub label: String,
    pub client_version: Option<String>,
    pub created_at_ms: i64,
    pub last_used_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub idle_timeout_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub recent_auth_until_ms: i64,
    pub recent_totp_until_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIpRow {
    pub client_id: String,
    pub ip: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug)]
pub struct PairingRow {
    pub user_code: String,
    pub device_label: String,
    pub requested_scopes: Vec<Scope>,
    pub approved_scopes: Option<Vec<Scope>>,
    pub account_id: Option<AccountId>,
    pub status: String,
    pub expires_at_ms: i64,
    pub next_poll_ms: i64,
    pub interval_s: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionKind {
    Object,
    Prefix,
}

impl DeletionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Prefix => "prefix",
        }
    }
}

pub type TwoFactorRow = (Option<String>, Option<Vec<u8>>, i64);
pub type TransferRow = (Vec<u8>, Option<Vec<u8>>);
pub type AuditRow = (String, String, Option<String>, i64);

pub fn scopes_to_string(scopes: &[Scope]) -> String {
    let mut names: Vec<&str> = scopes
        .iter()
        .map(|scope| match scope {
            Scope::Sync => "sync",
            Scope::Collector => "collector",
            Scope::Share => "share",
            Scope::Account => "account",
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names.join(",")
}

pub fn scopes_from_string(value: &str) -> Vec<Scope> {
    value
        .split(',')
        .filter_map(|name| match name {
            "sync" => Some(Scope::Sync),
            "collector" => Some(Scope::Collector),
            "share" => Some(Scope::Share),
            "account" => Some(Scope::Account),
            _ => None,
        })
        .collect()
}

fn client_kind_to_str(kind: ClientKind) -> &'static str {
    match kind {
        ClientKind::Desktop => "desktop",
        ClientKind::WebSession => "web-session",
        ClientKind::ManualToken => "manual-token",
    }
}

fn client_kind_from_str(value: &str) -> ClientKind {
    match value {
        "web-session" => ClientKind::WebSession,
        "manual-token" => ClientKind::ManualToken,
        _ => ClientKind::Desktop,
    }
}

fn parse_account_id(value: String) -> rusqlite::Result<AccountId> {
    value.parse().map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "account_id".into(), rusqlite::types::Type::Text)
    })
}

const ACCOUNT_COLUMNS: &str = "account_id, email, state, role, quota_bytes, max_vaults, collector_allowed, \
                               created_at_ms, wrapped_adk, usage_bytes, signup_message, sync_allowed";

fn account_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(AccountRow, String)> {
    let state: String = row.get(2)?;
    let role: String = row.get(3)?;
    let role = Role::parse(&role).map_err(|_| {
        rusqlite::Error::InvalidColumnType(3, "role".into(), rusqlite::types::Type::Text)
    })?;
    Ok((
        AccountRow {
            account_id: parse_account_id(row.get(0)?)?,
            email: row.get(1)?,
            state: AccountState::Unverified,
            role,
            quota_bytes: row.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
            max_vaults: row.get::<_, i64>(5)?.max(0) as u32,
            collector_allowed: row.get::<_, i64>(6)? != 0,
            created_at_ms: row.get(7)?,
            wrapped_adk: row.get(8)?,
            usage_bytes: row.get::<_, i64>(9)?.max(0) as u64,
            signup_message: row.get(10)?,
            sync_allowed: row.get::<_, i64>(11)? != 0,
        },
        state,
    ))
}

const TOKEN_COLUMNS: &str = "token_id, account_id, kind, client_kind, secret_hmac, scopes, label, client_version, \
                             created_at_ms, last_used_ms, expires_at_ms, idle_timeout_ms, revoked_at_ms, recent_auth_until_ms, recent_totp_until_ms";

fn token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRow> {
    Ok(TokenRow {
        token_id: row.get(0)?,
        account_id: parse_account_id(row.get(1)?)?,
        kind: row.get(2)?,
        client_kind: client_kind_from_str(&row.get::<_, String>(3)?),
        secret_hmac: row.get(4)?,
        scopes: scopes_from_string(&row.get::<_, String>(5)?),
        label: row.get(6)?,
        client_version: row.get(7)?,
        created_at_ms: row.get(8)?,
        last_used_ms: row.get(9)?,
        expires_at_ms: row.get(10)?,
        idle_timeout_ms: row.get(11)?,
        revoked_at_ms: row.get(12)?,
        recent_auth_until_ms: row.get(13)?,
        recent_totp_until_ms: row.get(14)?,
    })
}

pub struct Registry {
    conn: Connection,
}

pub struct NewToken<'a> {
    pub token_id: &'a str,
    pub account_id: &'a AccountId,
    pub kind: &'a str,
    pub client_kind: ClientKind,
    pub secret_hmac: &'a [u8],
    pub scopes: &'a [Scope],
    pub label: &'a str,
    pub client_version: Option<&'a str>,
    pub now_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub idle_timeout_ms: Option<i64>,
}

impl Registry {
    pub fn open(path: &Path, key: &[u8; 32]) -> DbResult<Self> {
        let mut conn = open_encrypted(path, key)?;
        migrate(&mut conn, MIGRATIONS)?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn setting(&self, key: &str) -> DbResult<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn create_account(
        &self,
        account_id: &AccountId,
        email: &str,
        state: AccountState,
        quota_bytes: Option<u64>,
        now_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO accounts (account_id, email, state, quota_bytes, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account_id.as_str(), email, state.as_str(), quota_bytes.map(|q| q as i64), now_ms],
        )?;
        Ok(())
    }

    fn finish_account(found: Option<(AccountRow, String)>) -> DbResult<Option<AccountRow>> {
        match found {
            Some((mut account, state)) => {
                account.state = AccountState::parse(&state)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    pub fn account(&self, account_id: &AccountId) -> DbResult<Option<AccountRow>> {
        let found = self
            .conn
            .query_row(
                &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE account_id = ?1"),
                [account_id.as_str()],
                account_from_row,
            )
            .optional()?;
        Self::finish_account(found)
    }

    pub fn account_by_email(&self, email: &str) -> DbResult<Option<AccountRow>> {
        let found = self
            .conn
            .query_row(
                &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE email = ?1"),
                [email],
                account_from_row,
            )
            .optional()?;
        Self::finish_account(found)
    }

    pub fn list_accounts(&self, state: Option<AccountState>) -> DbResult<Vec<AccountRow>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE (?1 IS NULL OR state = ?1) ORDER BY created_at_ms"
        ))?;
        let rows = statement.query_map([state.map(AccountState::as_str)], account_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            if let Some(account) = Self::finish_account(Some(row?))? {
                out.push(account);
            }
        }
        Ok(out)
    }

    pub fn collection_owner(&self, code: &str) -> DbResult<Option<AccountId>> {
        Ok(self
            .conn
            .query_row(
                "SELECT account_id FROM collection_index WHERE code = ?1",
                [code],
                |row| {
                    let value: String = row.get(0)?;
                    value.parse::<AccountId>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })
                },
            )
            .optional()?)
    }

    pub fn set_collection_index(
        &self,
        account_id: &AccountId,
        code: &str,
        listed: bool,
        title: &str,
        category: Option<&str>,
        updated_at_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute("INSERT INTO collection_index (code, account_id, listed, title, category, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(code) DO UPDATE SET account_id=excluded.account_id, listed=excluded.listed, title=excluded.title, category=excluded.category, updated_at_ms=excluded.updated_at_ms", params![code, account_id.as_str(), listed as i64, title, category, updated_at_ms])?;
        Ok(())
    }

    pub fn delete_collection_index(&self, account_id: &AccountId, code: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM collection_index WHERE account_id = ?1 AND code = ?2",
            params![account_id.as_str(), code],
        )?;
        Ok(())
    }

    pub fn listed_collections(&self) -> DbResult<Vec<CollectionIndexRow>> {
        let mut statement = self.conn.prepare("SELECT code, account_id, title, category, updated_at_ms FROM collection_index WHERE listed = 1 ORDER BY updated_at_ms DESC LIMIT 1000")?;
        let rows = statement.query_map([], |row| {
            let value: String = row.get(1)?;
            let owner = value.parse::<AccountId>().map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok((row.get(0)?, owner, row.get(2)?, row.get(3)?, row.get(4)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn set_state(&self, account_id: &AccountId, state: AccountState) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET state = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), state.as_str()],
        )? == 1)
    }

    pub fn set_wrapped_adk(&self, account_id: &AccountId, wrapped: Option<&[u8]>) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET wrapped_adk = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), wrapped],
        )?;
        Ok(())
    }

    pub fn set_quota(&self, account_id: &AccountId, quota_bytes: Option<u64>) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET quota_bytes = ?2, quota_warned = 0 WHERE account_id = ?1",
            params![account_id.as_str(), quota_bytes.map(|q| q as i64)],
        )? == 1)
    }

    pub fn set_sync_allowed(&self, account_id: &AccountId, allowed: bool) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET sync_allowed = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), allowed as i64],
        )? == 1)
    }

    pub fn set_collector_allowed(&self, account_id: &AccountId, allowed: bool) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET collector_allowed = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), allowed as i64],
        )? == 1)
    }

    pub fn set_role(&self, account_id: &AccountId, role: Role) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET role = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), role.as_str()],
        )? == 1)
    }

    pub fn set_max_vaults(&self, account_id: &AccountId, max_vaults: u32) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET max_vaults = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), max_vaults as i64],
        )? == 1)
    }

    pub fn set_usage(&self, account_id: &AccountId, usage_bytes: u64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET usage_bytes = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), usage_bytes as i64],
        )?;
        Ok(())
    }

    pub fn role_count(&self, role: Role) -> DbResult<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM accounts WHERE role = ?1",
            [role.as_str()],
            |row| row.get(0),
        )?)
    }

    pub fn delete_account(&self, account_id: &AccountId) -> DbResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM audit_log WHERE target_account = ?1",
            [account_id.as_str()],
        )?;
        tx.execute(
            "DELETE FROM accounts WHERE account_id = ?1",
            [account_id.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn password_hash(&self, account_id: &AccountId) -> DbResult<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT password_hash FROM accounts WHERE account_id = ?1",
                [account_id.as_str()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn set_password_hash(&self, account_id: &AccountId, hash: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET password_hash = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), hash],
        )?;
        Ok(())
    }

    pub fn set_email_verified(&self, account_id: &AccountId, now_ms: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET email_verified_at_ms = COALESCE(email_verified_at_ms, ?2) WHERE account_id = ?1",
            params![account_id.as_str(), now_ms],
        )?;
        Ok(())
    }

    pub fn set_signup_message(&self, account_id: &AccountId, message: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET signup_message = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), message],
        )?;
        Ok(())
    }

    pub fn insert_auth_token(
        &self,
        token_hmac: &[u8; 32],
        account_id: &AccountId,
        purpose: &str,
        expires_at_ms: i64,
        data: Option<&str>,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO auth_tokens (token_hmac, account_id, purpose, expires_at_ms, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![token_hmac.as_slice(), account_id.as_str(), purpose, expires_at_ms, data],
        )?;
        Ok(())
    }

    pub fn use_auth_token(
        &self,
        token_hmac: &[u8; 32],
        purpose: &str,
        now_ms: i64,
        max_attempts: i64,
    ) -> DbResult<Option<(AccountId, Option<String>)>> {
        let found: Option<(String, i64, Option<String>)> = self
            .conn
            .query_row(
                "UPDATE auth_tokens SET attempts = attempts + 1
                 WHERE token_hmac = ?1 AND purpose = ?2 AND expires_at_ms > ?3
                 RETURNING account_id, attempts, data",
                params![token_hmac.as_slice(), purpose, now_ms],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match found {
            Some((account, attempts, data)) if attempts <= max_attempts => {
                Ok(Some((parse_account_id(account)?, data)))
            }
            Some(_) => {
                self.delete_auth_token(token_hmac)?;
                Ok(None)
            }
            None => Ok(None),
        }
    }

    pub fn delete_auth_token(&self, token_hmac: &[u8; 32]) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM auth_tokens WHERE token_hmac = ?1",
            [token_hmac.as_slice()],
        )?;
        Ok(())
    }

    pub fn set_email_code(
        &self,
        account_id: &AccountId,
        purpose: &str,
        code_hmac: &[u8; 32],
        expires_at_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO email_codes (account_id, purpose, code_hmac, expires_at_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account_id, purpose) DO UPDATE
             SET code_hmac = excluded.code_hmac, expires_at_ms = excluded.expires_at_ms, attempts = 0",
            params![account_id.as_str(), purpose, code_hmac.as_slice(), expires_at_ms],
        )?;
        Ok(())
    }

    pub fn use_email_code(
        &self,
        account_id: &AccountId,
        purpose: &str,
        code_hmac: &[u8; 32],
        now_ms: i64,
    ) -> DbResult<bool> {
        let stored: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "UPDATE email_codes SET attempts = attempts + 1
                 WHERE account_id = ?1 AND purpose = ?2 AND expires_at_ms > ?3
                 RETURNING code_hmac, attempts",
                params![account_id.as_str(), purpose, now_ms],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match stored {
            Some((stored, attempts))
                if attempts <= 5 && crate::crypto::constant_time_eq(&stored, code_hmac) =>
            {
                self.conn.execute(
                    "DELETE FROM email_codes WHERE account_id = ?1 AND purpose = ?2",
                    params![account_id.as_str(), purpose],
                )?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn set_totp_pending(&self, account_id: &AccountId, wrapped_secret: &[u8]) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET totp_pending_wrapped = ?2 WHERE account_id = ?1",
            params![account_id.as_str(), wrapped_secret],
        )?;
        Ok(())
    }

    pub fn totp_pending(&self, account_id: &AccountId) -> DbResult<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT totp_pending_wrapped FROM accounts WHERE account_id = ?1",
                [account_id.as_str()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn activate_pending_totp(&self, account_id: &AccountId, step: i64) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET twofa_method = 'totp', totp_secret_wrapped = totp_pending_wrapped,
                                 totp_pending_wrapped = NULL, totp_last_step = ?2
             WHERE account_id = ?1 AND totp_pending_wrapped IS NOT NULL",
            params![account_id.as_str(), step],
        )? == 1)
    }

    pub fn set_twofa_email(&self, account_id: &AccountId) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET twofa_method = 'email', totp_secret_wrapped = NULL WHERE account_id = ?1",
            [account_id.as_str()],
        )?;
        Ok(())
    }

    pub fn twofa(&self, account_id: &AccountId) -> DbResult<Option<TwoFactorRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT twofa_method, totp_secret_wrapped, totp_last_step FROM accounts WHERE account_id = ?1",
                [account_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?)
    }

    #[cfg(test)]
    pub fn set_totp(&self, account_id: &AccountId, wrapped_secret: &[u8]) -> DbResult<()> {
        self.conn.execute(
            "UPDATE accounts SET twofa_method = 'totp', totp_secret_wrapped = ?2, totp_last_step = 0 WHERE account_id = ?1",
            params![account_id.as_str(), wrapped_secret],
        )?;
        Ok(())
    }

    pub fn reset_twofa(&self, account_id: &AccountId) -> DbResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE accounts SET twofa_method = NULL, totp_secret_wrapped = NULL, totp_last_step = 0 WHERE account_id = ?1",
            [account_id.as_str()],
        )?;
        tx.execute(
            "DELETE FROM recovery_codes WHERE account_id = ?1",
            [account_id.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn advance_totp_step(&self, account_id: &AccountId, step: i64) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE accounts SET totp_last_step = ?2 WHERE account_id = ?1 AND totp_last_step < ?2",
            params![account_id.as_str(), step],
        )? == 1)
    }

    pub fn replace_recovery_codes(
        &self,
        account_id: &AccountId,
        code_hmacs: &[[u8; 32]],
    ) -> DbResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM recovery_codes WHERE account_id = ?1",
            [account_id.as_str()],
        )?;
        for code in code_hmacs {
            tx.execute(
                "INSERT INTO recovery_codes (account_id, code_hmac) VALUES (?1, ?2)",
                params![account_id.as_str(), code.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn recovery_codes_left(&self, account_id: &AccountId) -> DbResult<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM recovery_codes WHERE account_id = ?1 AND used_at_ms IS NULL",
            [account_id.as_str()],
            |row| row.get(0),
        )?)
    }

    pub fn use_recovery_code(
        &self,
        account_id: &AccountId,
        code_hmac: &[u8; 32],
        now_ms: i64,
    ) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE recovery_codes SET used_at_ms = ?3 WHERE account_id = ?1 AND code_hmac = ?2 AND used_at_ms IS NULL",
            params![account_id.as_str(), code_hmac.as_slice(), now_ms],
        )? == 1)
    }

    pub fn insert_token(&self, token: &NewToken<'_>) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO tokens (token_id, account_id, kind, client_kind, secret_hmac, scopes, label, client_version,
                                 created_at_ms, expires_at_ms, idle_timeout_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                token.token_id,
                token.account_id.as_str(),
                token.kind,
                client_kind_to_str(token.client_kind),
                token.secret_hmac,
                scopes_to_string(token.scopes),
                token.label,
                token.client_version,
                token.now_ms,
                token.expires_at_ms,
                token.idle_timeout_ms,
            ],
        )?;
        Ok(())
    }

    pub fn token(&self, token_id: &str) -> DbResult<Option<TokenRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {TOKEN_COLUMNS} FROM tokens WHERE token_id = ?1"),
                [token_id],
                token_from_row,
            )
            .optional()?)
    }

    pub fn tokens_for(&self, account_id: &AccountId) -> DbResult<Vec<TokenRow>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {TOKEN_COLUMNS} FROM tokens WHERE account_id = ?1 ORDER BY created_at_ms"
        ))?;
        let rows = statement.query_map([account_id.as_str()], token_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn touch_token(
        &self,
        token_id: &str,
        client_version: Option<&str>,
        now_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "UPDATE tokens SET last_used_ms = ?2, client_version = COALESCE(?3, client_version) WHERE token_id = ?1",
            params![token_id, now_ms, client_version],
        )?;
        Ok(())
    }

    pub fn set_recent_totp(&self, token_id: &str, until_ms: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE tokens SET recent_totp_until_ms = ?2, recent_auth_until_ms = ?2 WHERE token_id = ?1",
            params![token_id, until_ms],
        )?;
        Ok(())
    }

    pub fn set_recent_auth(&self, token_id: &str, until_ms: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE tokens SET recent_auth_until_ms = ?2 WHERE token_id = ?1",
            params![token_id, until_ms],
        )?;
        Ok(())
    }

    pub fn revoke_token(
        &self,
        account_id: &AccountId,
        token_id: &str,
        by: &str,
        now_ms: i64,
    ) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE tokens SET revoked_at_ms = ?3, revoked_by = ?4
             WHERE account_id = ?1 AND token_id = ?2 AND revoked_at_ms IS NULL",
            params![account_id.as_str(), token_id, now_ms, by],
        )? == 1)
    }

    pub fn revoke_all_except(
        &self,
        account_id: &AccountId,
        keep: &str,
        by: &str,
        now_ms: i64,
    ) -> DbResult<usize> {
        Ok(self.conn.execute(
            "UPDATE tokens SET revoked_at_ms = ?3, revoked_by = ?4
             WHERE account_id = ?1 AND token_id != ?2 AND revoked_at_ms IS NULL",
            params![account_id.as_str(), keep, now_ms, by],
        )?)
    }

    pub fn count_live_tokens(&self, account_id: &AccountId) -> DbResult<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM tokens WHERE account_id = ?1 AND revoked_at_ms IS NULL",
            [account_id.as_str()],
            |row| row.get(0),
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_client_ip(
        &self,
        account_id: &AccountId,
        client_id: &str,
        ip: &str,
        city: Option<&str>,
        region: Option<&str>,
        country: Option<&str>,
        now_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO client_ips (client_id, account_id, ip, city, region, country, first_seen_ms, last_seen_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT (client_id, ip) DO UPDATE SET last_seen_ms = excluded.last_seen_ms",
            params![client_id, account_id.as_str(), ip, city, region, country, now_ms],
        )?;
        Ok(())
    }

    pub fn client_ips(&self, account_id: &AccountId) -> DbResult<Vec<ClientIpRow>> {
        let mut statement = self.conn.prepare(
            "SELECT client_id, ip, city, region, country, first_seen_ms, last_seen_ms
             FROM client_ips WHERE account_id = ?1 ORDER BY last_seen_ms DESC",
        )?;
        let rows = statement.query_map([account_id.as_str()], |row| {
            Ok(ClientIpRow {
                client_id: row.get(0)?,
                ip: row.get(1)?,
                city: row.get(2)?,
                region: row.get(3)?,
                country: row.get(4)?,
                first_seen_ms: row.get(5)?,
                last_seen_ms: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn clear_client_ips(
        &self,
        account_id: &AccountId,
        client_id: Option<&str>,
    ) -> DbResult<usize> {
        Ok(self.conn.execute(
            "DELETE FROM client_ips WHERE account_id = ?1 AND (?2 IS NULL OR client_id = ?2)",
            params![account_id.as_str(), client_id],
        )?)
    }

    pub fn prune_client_ips(&self, older_than_ms: i64) -> DbResult<usize> {
        Ok(self.conn.execute(
            "DELETE FROM client_ips WHERE last_seen_ms < ?1",
            [older_than_ms],
        )?)
    }

    pub fn insert_pairing(
        &self,
        device_code_hmac: &[u8],
        user_code: &str,
        device_label: &str,
        requested_scopes: &[Scope],
        expires_at_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO device_pairings (device_code_hmac, user_code, device_label, requested_scopes, status, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
            params![device_code_hmac, user_code, device_label, scopes_to_string(requested_scopes), expires_at_ms],
        )?;
        Ok(())
    }

    fn pairing_where(
        &self,
        clause: &str,
        value: &dyn rusqlite::ToSql,
    ) -> DbResult<Option<PairingRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT user_code, device_label, requested_scopes, approved_scopes, account_id, status,
                            expires_at_ms, next_poll_ms, interval_s
                     FROM device_pairings WHERE {clause} = ?1"
                ),
                [value],
                |row| {
                    Ok(PairingRow {
                        user_code: row.get(0)?,
                        device_label: row.get(1)?,
                        requested_scopes: scopes_from_string(&row.get::<_, String>(2)?),
                        approved_scopes: row.get::<_, Option<String>>(3)?.map(|s| scopes_from_string(&s)),
                        account_id: row.get::<_, Option<String>>(4)?.map(parse_account_id).transpose()?,
                        status: row.get(5)?,
                        expires_at_ms: row.get(6)?,
                        next_poll_ms: row.get(7)?,
                        interval_s: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn pairing_by_device_code(&self, device_code_hmac: &[u8]) -> DbResult<Option<PairingRow>> {
        self.pairing_where("device_code_hmac", &device_code_hmac)
    }

    pub fn pairing_by_user_code(&self, user_code: &str) -> DbResult<Option<PairingRow>> {
        self.pairing_where("user_code", &user_code)
    }

    pub fn decide_pairing(
        &self,
        user_code: &str,
        account_id: &AccountId,
        approved_scopes: Option<&[Scope]>,
    ) -> DbResult<bool> {
        let (status, scopes) = match approved_scopes {
            Some(scopes) => ("approved", Some(scopes_to_string(scopes))),
            None => ("denied", None),
        };
        Ok(self.conn.execute(
            "UPDATE device_pairings SET status = ?2, approved_scopes = ?3, account_id = ?4
             WHERE user_code = ?1 AND status = 'pending'",
            params![user_code, status, scopes, account_id.as_str()],
        )? == 1)
    }

    pub fn set_pairing_poll(
        &self,
        device_code_hmac: &[u8],
        next_poll_ms: i64,
        interval_s: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "UPDATE device_pairings SET next_poll_ms = ?2, interval_s = ?3 WHERE device_code_hmac = ?1",
            params![device_code_hmac, next_poll_ms, interval_s],
        )?;
        Ok(())
    }

    pub fn delete_pairing(&self, device_code_hmac: &[u8]) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM device_pairings WHERE device_code_hmac = ?1",
            [device_code_hmac],
        )?;
        Ok(())
    }

    pub fn insert_transfer(
        &self,
        transfer_id: &str,
        account_id: &AccountId,
        epk: &[u8],
        expires_at_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO transfers (transfer_id, account_id, epk, expires_at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![transfer_id, account_id.as_str(), epk, expires_at_ms],
        )?;
        Ok(())
    }

    pub fn transfer(
        &self,
        transfer_id: &str,
        account_id: &AccountId,
        now_ms: i64,
    ) -> DbResult<Option<TransferRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT epk, sealed FROM transfers WHERE transfer_id = ?1 AND account_id = ?2 AND expires_at_ms > ?3",
                params![transfer_id, account_id.as_str(), now_ms],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn complete_transfer(
        &self,
        transfer_id: &str,
        account_id: &AccountId,
        sealed: &[u8],
        now_ms: i64,
    ) -> DbResult<bool> {
        Ok(self.conn.execute(
            "UPDATE transfers SET sealed = ?3
             WHERE transfer_id = ?1 AND account_id = ?2 AND sealed IS NULL AND expires_at_ms > ?4",
            params![transfer_id, account_id.as_str(), sealed, now_ms],
        )? == 1)
    }

    pub fn delete_transfer(&self, transfer_id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM transfers WHERE transfer_id = ?1",
            [transfer_id],
        )?;
        Ok(())
    }

    pub fn prune_expired(&self, now_ms: i64) -> DbResult<()> {
        self.conn
            .execute("DELETE FROM transfers WHERE expires_at_ms <= ?1", [now_ms])?;
        self.conn.execute(
            "DELETE FROM device_pairings WHERE expires_at_ms <= ?1",
            [now_ms],
        )?;
        self.conn.execute(
            "DELETE FROM email_codes WHERE expires_at_ms <= ?1",
            [now_ms],
        )?;
        self.conn.execute(
            "DELETE FROM auth_tokens WHERE expires_at_ms <= ?1",
            [now_ms],
        )?;
        Ok(())
    }

    pub fn enqueue_deletions(&self, items: &[(DeletionKind, String)]) -> DbResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        for (kind, target) in items {
            tx.execute(
                "INSERT INTO blob_deletions (target, kind) VALUES (?1, ?2)
                 ON CONFLICT (target) DO UPDATE SET next_attempt_ms = 0",
                params![target, kind.as_str()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn due_deletions(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> DbResult<Vec<(DeletionKind, String, i64)>> {
        let mut statement = self.conn.prepare(
            "SELECT kind, target, attempts FROM blob_deletions WHERE next_attempt_ms <= ?1
             ORDER BY kind DESC, next_attempt_ms LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_ms, i64::from(limit)], |row| {
            let kind: String = row.get(0)?;
            Ok((
                if kind == "prefix" {
                    DeletionKind::Prefix
                } else {
                    DeletionKind::Object
                },
                row.get(1)?,
                row.get(2)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn finish_deletion(&self, target: &str) -> DbResult<()> {
        self.conn
            .execute("DELETE FROM blob_deletions WHERE target = ?1", [target])?;
        Ok(())
    }

    pub fn retry_deletion(&self, target: &str, next_attempt_ms: i64) -> DbResult<()> {
        self.conn.execute(
            "UPDATE blob_deletions SET attempts = attempts + 1, next_attempt_ms = ?2 WHERE target = ?1",
            params![target, next_attempt_ms],
        )?;
        Ok(())
    }

    pub fn pending_deletions(&self) -> DbResult<i64> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM blob_deletions", [], |row| row.get(0))?)
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        target: Option<&AccountId>,
        now_ms: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO audit_log (actor, action, target_account, at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![actor, action, target.map(AccountId::as_str), now_ms],
        )?;
        Ok(())
    }

    pub fn audit_entries(&self, target: Option<&AccountId>) -> DbResult<Vec<AuditRow>> {
        let mut statement = self.conn.prepare(
            "SELECT actor, action, target_account, at_ms FROM audit_log
             WHERE (?1 IS NULL OR target_account = ?1) ORDER BY id DESC LIMIT 500",
        )?;
        let rows = statement.query_map([target.map(AccountId::as_str)], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> (tempfile::TempDir, Registry) {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::open(&dir.path().join("registry.db"), &[3; 32]).unwrap();
        (dir, registry)
    }

    #[test]
    fn account_lifecycle() {
        let (_dir, registry) = registry();
        let id = AccountId::random().unwrap();
        registry
            .create_account(
                &id,
                "Me@Example.com",
                AccountState::Pending,
                Some(1 << 30),
                1,
            )
            .unwrap();
        let account = registry
            .account_by_email("me@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(account.account_id, id);
        assert_eq!(account.state, AccountState::Pending);
        assert_eq!(account.quota_bytes, Some(1 << 30));
        assert_eq!(account.role, Role::User);
        assert!(registry.set_role(&id, Role::Owner).unwrap());
        assert_eq!(registry.account(&id).unwrap().unwrap().role, Role::Owner);
        assert_eq!(registry.role_count(Role::Owner).unwrap(), 1);
        assert_eq!(registry.role_count(Role::Admin).unwrap(), 0);
        assert!(registry.set_state(&id, AccountState::Active).unwrap());
        assert!(registry.set_quota(&id, None).unwrap());
        let account = registry.account(&id).unwrap().unwrap();
        assert_eq!(account.state, AccountState::Active);
        assert_eq!(account.quota_bytes, None);
        assert_eq!(
            registry
                .list_accounts(Some(AccountState::Active))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            registry
                .list_accounts(Some(AccountState::Pending))
                .unwrap()
                .len(),
            0
        );
        registry.audit("cli", "approve", Some(&id), 2).unwrap();
        registry.delete_account(&id).unwrap();
        assert!(registry.account(&id).unwrap().is_none());
        assert!(registry.audit_entries(Some(&id)).unwrap().is_empty());
    }

    #[test]
    fn tokens_and_revocation() {
        let (_dir, registry) = registry();
        let id = AccountId::random().unwrap();
        registry
            .create_account(&id, "a@b.c", AccountState::Active, None, 1)
            .unwrap();
        for token_id in ["t1", "t2", "t3"] {
            registry
                .insert_token(&NewToken {
                    token_id,
                    account_id: &id,
                    kind: "api",
                    client_kind: ClientKind::Desktop,
                    secret_hmac: &[1, 2, 3],
                    scopes: &[Scope::Sync, Scope::Account],
                    label: "PC",
                    client_version: None,
                    now_ms: 1,
                    expires_at_ms: None,
                    idle_timeout_ms: None,
                })
                .unwrap();
        }
        let token = registry.token("t1").unwrap().unwrap();
        assert_eq!(token.scopes, vec![Scope::Account, Scope::Sync]);
        assert!(registry.revoke_token(&id, "t1", "t2", 5).unwrap());
        assert!(!registry.revoke_token(&id, "t1", "t2", 6).unwrap());
        assert_eq!(registry.revoke_all_except(&id, "t2", "t2", 7).unwrap(), 1);
        assert_eq!(registry.count_live_tokens(&id).unwrap(), 1);
        let other = AccountId::random().unwrap();
        assert!(!registry.revoke_token(&other, "t2", "x", 8).unwrap());
    }

    #[test]
    fn client_ip_history() {
        let (_dir, registry) = registry();
        let id = AccountId::random().unwrap();
        registry
            .create_account(&id, "a@b.c", AccountState::Active, None, 1)
            .unwrap();
        registry
            .record_client_ip(
                &id,
                "t1",
                "203.0.113.1",
                Some("Paris"),
                None,
                Some("FR"),
                100,
            )
            .unwrap();
        registry
            .record_client_ip(
                &id,
                "t1",
                "203.0.113.1",
                Some("Paris"),
                None,
                Some("FR"),
                200,
            )
            .unwrap();
        registry
            .record_client_ip(&id, "t1", "198.51.100.2", None, None, None, 300)
            .unwrap();
        let rows = registry.client_ips(&id).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].first_seen_ms, 100);
        assert_eq!(rows[1].last_seen_ms, 200);
        assert_eq!(registry.prune_client_ips(250).unwrap(), 1);
        assert_eq!(registry.clear_client_ips(&id, Some("t1")).unwrap(), 1);
    }

    #[test]
    fn pairing_flow() {
        let (_dir, registry) = registry();
        let id = AccountId::random().unwrap();
        registry
            .create_account(&id, "a@b.c", AccountState::Active, None, 1)
            .unwrap();
        registry
            .insert_pairing(b"hash", "4K7M-X9QD", "PC", &[Scope::Sync], 1000)
            .unwrap();
        assert!(
            registry
                .decide_pairing("4K7M-X9QD", &id, Some(&[Scope::Sync]))
                .unwrap()
        );
        assert!(!registry.decide_pairing("4K7M-X9QD", &id, None).unwrap());
        let pairing = registry.pairing_by_device_code(b"hash").unwrap().unwrap();
        assert_eq!(pairing.status, "approved");
        assert_eq!(pairing.account_id, Some(id));
        registry.prune_expired(1000).unwrap();
        assert!(
            registry
                .pairing_by_user_code("4K7M-X9QD")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn transfers_are_scoped_to_account_and_single_use() {
        let (_dir, registry) = registry();
        let id = AccountId::random().unwrap();
        let other = AccountId::random().unwrap();
        registry
            .create_account(&id, "a@b.c", AccountState::Active, None, 1)
            .unwrap();
        registry
            .insert_transfer("ABCDEFGH", &id, &[9; 32], 1000)
            .unwrap();
        assert!(registry.transfer("ABCDEFGH", &other, 1).unwrap().is_none());
        assert!(
            registry
                .complete_transfer("ABCDEFGH", &id, b"sealed", 1)
                .unwrap()
        );
        assert!(
            !registry
                .complete_transfer("ABCDEFGH", &id, b"again", 1)
                .unwrap()
        );
        assert_eq!(
            registry
                .transfer("ABCDEFGH", &id, 1)
                .unwrap()
                .unwrap()
                .1
                .unwrap(),
            b"sealed"
        );
        assert!(registry.transfer("ABCDEFGH", &id, 1000).unwrap().is_none());
    }
}

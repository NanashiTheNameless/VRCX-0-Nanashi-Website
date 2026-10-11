use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use vrcx_0_nanashi_website_protocol::api::{Scope, headers};
use vrcx_0_nanashi_website_protocol::token::{self, TokenKind};

use crate::crypto::constant_time_eq;
use crate::db::registry::{AccountRow, AccountState, TokenRow};
use crate::http::{ApiErr, ApiResult};
use crate::rate;
use crate::state::Shared;
use crate::util::now_ms;

pub const TOKEN_HMAC_PURPOSE: &str = "token";

pub struct ApiAuth {
    pub account: AccountRow,
    pub token: TokenRow,
    pub now_ms: i64,
}

impl ApiAuth {
    pub fn require_sync(&self, scope: Scope) -> ApiResult<()> {
        self.require(scope)?;
        self.require_sync_enabled()
    }

    pub fn require_sync_enabled(&self) -> ApiResult<()> {
        if self.account.sync_allowed {
            Ok(())
        } else {
            Err(ApiErr::sync_disabled())
        }
    }

    pub fn require_active(&self) -> ApiResult<()> {
        if self.account.state == AccountState::Active {
            Ok(())
        } else {
            Err(ApiErr::new(
                axum::http::StatusCode::FORBIDDEN,
                "account_not_active",
                "This account is not active.",
            ))
        }
    }

    pub fn require_admin_totp(&self, totp_enrolled: bool) -> ApiResult<()> {
        self.require_active()?;
        if !self.account.role.can_administer() {
            return Err(ApiErr::new(
                axum::http::StatusCode::FORBIDDEN,
                "not_admin",
                "Admins only.",
            ));
        }
        if !totp_enrolled {
            return Err(ApiErr::new(
                axum::http::StatusCode::FORBIDDEN,
                "totp_required",
                "Set up an authenticator app to use your admin privileges.",
            ));
        }
        if self.token.recent_totp_until_ms <= self.now_ms {
            return Err(ApiErr::new(
                axum::http::StatusCode::FORBIDDEN,
                "totp_reauth_required",
                "Enter a code from your authenticator app first.",
            ));
        }
        Ok(())
    }

    pub fn require(&self, scope: Scope) -> ApiResult<()> {
        if self.token.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(ApiErr::forbidden_scope())
        }
    }

    pub fn require_recent_auth_on_web(&self) -> ApiResult<()> {
        if self.token.kind == "session" {
            self.require_recent_auth()
        } else {
            Ok(())
        }
    }

    pub fn require_recent_auth(&self) -> ApiResult<()> {
        if self.token.recent_auth_until_ms > self.now_ms {
            Ok(())
        } else {
            Err(ApiErr::reauth_required())
        }
    }
}

fn header_text(headers: &HeaderMap, name: &str, max_len: usize) -> Option<String> {
    let value = headers.get(name)?;
    let text = String::from_utf8_lossy(value.as_bytes());
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect();
    let cleaned = cleaned.trim().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

pub struct ClientOrigin {
    pub ip: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

impl ClientOrigin {
    pub fn rate_key(&self) -> String {
        self.ip.clone().unwrap_or_else(|| "unknown".into())
    }

    pub fn from_headers(headers: &HeaderMap) -> Self {
        let ip = header_text(headers, "cf-connecting-ip", 64)
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok());
        Self {
            ip,
            city: header_text(headers, "cf-ipcity", 100),
            region: header_text(headers, "cf-region", 100),
            country: header_text(headers, "cf-ipcountry", 8),
        }
    }
}

impl FromRequestParts<Shared> for ApiAuth {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let path = parts
            .extensions
            .get::<axum::extract::OriginalUri>()
            .map(|uri| uri.0.path().to_owned())
            .unwrap_or_else(|| parts.uri.path().to_owned());
        if path.starts_with("/web/") {
            let auth = authenticate(parts, state, TokenKind::Session).await?;
            auth.require_active()?;
            Ok(auth)
        } else {
            authenticate(parts, state, TokenKind::Api).await
        }
    }
}

pub struct WebAuth(pub ApiAuth);

impl std::ops::Deref for WebAuth {
    type Target = ApiAuth;

    fn deref(&self) -> &ApiAuth {
        &self.0
    }
}

impl FromRequestParts<Shared> for WebAuth {
    type Rejection = ApiErr;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> Result<Self, Self::Rejection> {
        let path = parts
            .extensions
            .get::<axum::extract::OriginalUri>()
            .map(|uri| uri.0.path().to_owned())
            .unwrap_or_else(|| parts.uri.path().to_owned());
        let auth = authenticate(parts, state, TokenKind::Session).await?;
        if !matches!(path.as_str(), "/web/v1/me" | "/web/v1/session") {
            auth.require_active()?;
        }
        Ok(WebAuth(auth))
    }
}

async fn authenticate(
    parts: &mut Parts,
    state: &Shared,
    kind: TokenKind,
) -> Result<ApiAuth, ApiErr> {
    {
        let origin = ClientOrigin::from_headers(&parts.headers);
        let rate_key = origin.rate_key();
        state
            .limiter
            .check(rate::AUTH_FAILURES_IP, &rate_key, now_ms())
            .map_err(ApiErr::rate_limited)?;
        let fail = |token_id: Option<&str>| {
            state
                .limiter
                .fail(rate::AUTH_FAILURES_IP, &rate_key, now_ms());
            if let Some(id) = token_id {
                state.limiter.fail(rate::AUTH_FAILURES_TOKEN, id, now_ms());
            }
            ApiErr::unauthorized()
        };
        let Some(bearer) = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return Err(ApiErr::unauthorized());
        };
        let Ok(parsed) = token::parse(bearer.trim(), kind) else {
            return Err(fail(None));
        };
        state
            .limiter
            .check(rate::AUTH_FAILURES_TOKEN, &parsed.id, now_ms())
            .map_err(ApiErr::rate_limited)?;
        let token_id = parsed.id.clone();
        let client_version = header_text(&parts.headers, headers::CLIENT, 200);
        let result = state
            .run(move |state| {
                let now = now_ms();
                let registry = state.registry();
                let token = registry
                    .token(&parsed.id)?
                    .ok_or_else(ApiErr::unauthorized)?;
                let expected = state.keys.hmac(TOKEN_HMAC_PURPOSE, &parsed.secret);
                let expected_kind = match kind {
                    TokenKind::Api => "api",
                    TokenKind::Session => "session",
                };
                let valid = token.kind == expected_kind
                    && constant_time_eq(&expected, &token.secret_hmac)
                    && token.revoked_at_ms.is_none()
                    && token.expires_at_ms.is_none_or(|expires| expires > now)
                    && token.idle_timeout_ms.is_none_or(|idle| {
                        token.last_used_ms.unwrap_or(token.created_at_ms) + idle > now
                    });
                if !valid {
                    return Err(ApiErr::unauthorized());
                }
                let account = registry
                    .account(&token.account_id)?
                    .ok_or_else(ApiErr::unauthorized)?;
                let allowed = match kind {
                    TokenKind::Api => account.state == AccountState::Active,
                    TokenKind::Session => matches!(
                        account.state,
                        AccountState::Active | AccountState::Pending | AccountState::Suspended
                    ),
                };
                if !allowed {
                    return Err(ApiErr::unauthorized());
                }
                if let Some(ip) = &origin.ip
                    && state.should_write_client(&token.token_id, ip, now)
                {
                    registry.record_client_ip(
                        &account.account_id,
                        &token.token_id,
                        ip,
                        origin.city.as_deref(),
                        origin.region.as_deref(),
                        origin.country.as_deref(),
                        now,
                    )?;
                    registry.touch_token(&token.token_id, client_version.as_deref(), now)?;
                } else if token
                    .last_used_ms
                    .is_none_or(|last| now - last > crate::state::CLIENT_WRITE_INTERVAL_MS)
                {
                    registry.touch_token(&token.token_id, client_version.as_deref(), now)?;
                }
                Ok(ApiAuth {
                    account,
                    token,
                    now_ms: now,
                })
            })
            .await;
        match result {
            Err(error) if error.status == axum::http::StatusCode::UNAUTHORIZED => {
                Err(fail(Some(&token_id)))
            }
            other => other,
        }
    }
}

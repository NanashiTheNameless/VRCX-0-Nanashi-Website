use altcha::{
    CreateChallengeOptions, Payload, VerifySolutionOptions, create_challenge, verify_solution,
};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use data_encoding::{BASE64, BASE64_NOPAD};
use serde::{Deserialize, Serialize};
use vrcx_0_nanashi_website_protocol::api::{ClientKind, ReauthMethod, Scope, codes};
use vrcx_0_nanashi_website_protocol::b64;
use vrcx_0_nanashi_website_protocol::ids::AccountId;
use vrcx_0_nanashi_website_protocol::token::{self, TokenKind};
use zeroize::Zeroizing;

use crate::auth::{ClientOrigin, TOKEN_HMAC_PURPOSE, WebAuth};
use crate::db::registry::{AccountRow, AccountState, NewToken};
use crate::http::{ApiErr, ApiResult};
use crate::mail;
use crate::passwords;
use crate::rate;
use crate::recovery;
use crate::routes::v1::{RECENT_AUTH_MS, check_second_factor};
use crate::state::{AppState, Shared};
use crate::totp;
use crate::util::{DAY_MS, now_ms, random_bytes};

pub const SESSION_IDLE_MS: i64 = 12 * 60 * 60 * 1000;
pub const SESSION_MAX_MS: i64 = 30 * DAY_MS;
const LINK_TTL_MS: i64 = 30 * 60 * 1000;
const CHALLENGE_TTL_MS: i64 = 15 * 60 * 1000;
const CODE_TTL_MS: i64 = 10 * 60 * 1000;
pub(crate) const INVITE_TTL_MS: i64 = 7 * DAY_MS;
pub(crate) const AUTH_TOKEN_PURPOSE: &str = "auth-token";
const EMAIL_CODE_PURPOSE: &str = "email-code";
const ALL_SCOPES: &[Scope] = &[Scope::Sync, Scope::Collector, Scope::Share, Scope::Account];

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/auth/signup", post(signup))
        .route("/auth/altcha/challenge", get(altcha_challenge))
        .route("/auth/verify", post(verify))
        .route("/auth/verify/resend", post(resend_verification))
        .route("/auth/enroll/totp", post(enroll_totp_start))
        .route("/auth/enroll/totp/confirm", post(enroll_totp_confirm))
        .route("/auth/enroll/email", post(enroll_email_start))
        .route("/auth/enroll/email/confirm", post(enroll_email_confirm))
        .route("/auth/login", post(login))
        .route("/auth/login/email-code", post(login_email_code))
        .route("/auth/login/2fa", post(login_second_factor))
        .route("/auth/reset", post(reset_start))
        .route("/auth/reset/finish", post(reset_finish))
        .route("/session", delete(sign_out))
        .route("/me", get(me))
        .route("/reauth", post(reauth))
        .route("/reauth/email-code", post(reauth_email_code))
        .route("/security/twofa/totp", post(twofa_totp_start))
        .route("/security/twofa/totp/confirm", post(twofa_totp_confirm))
        .route("/security/twofa/email", post(twofa_email_start))
        .route("/security/twofa/email/confirm", post(twofa_email_confirm))
        .route("/recovery-codes", post(regenerate_recovery_codes))
        .route("/password", put(change_password))
        .route("/account", delete(delete_account))
        .route("/tokens", post(create_token))
        .route("/pair/{code}", get(pairing_info))
        .route("/pair/{code}/approve", post(pairing_approve))
        .route("/pair/{code}/deny", post(pairing_deny))
        .route(
            "/envelopes",
            get(list_envelopes)
                .post(create_envelope)
                .delete(delete_all_envelopes),
        )
        .route(
            "/envelopes/{envelope_id}",
            get(get_envelope).delete(delete_envelope),
        )
        .route("/admin/accounts", get(admin_accounts))
        .route(
            "/admin/accounts/{account_id}",
            get(admin_account).delete(admin_delete_account),
        )
        .route("/admin/accounts/{account_id}/approve", post(admin_approve))
        .route("/admin/accounts/{account_id}/suspend", post(admin_suspend))
        .route("/admin/accounts/{account_id}/resume", post(admin_resume))
        .route("/admin/accounts/{account_id}/role", put(admin_role))
        .route("/admin/accounts/{account_id}/sync", put(admin_sync))
        .route("/admin/accounts/{account_id}/deny", post(admin_deny))
        .route(
            "/admin/accounts/{account_id}/reset-2fa",
            post(admin_reset_2fa),
        )
        .route("/admin/accounts/{account_id}/limits", put(admin_limits))
        .route(
            "/admin/accounts/{account_id}/collector",
            put(admin_collector),
        )
        .route("/admin/invites", post(admin_invite))
        .route(
            "/admin/settings",
            get(admin_settings).put(admin_update_settings),
        )
        .route("/admin/audit", get(admin_audit))
        .merge(crate::routes::v1::shared_routes())
        .fallback(crate::routes::api_not_found)
}

async fn altcha_challenge(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<Json<altcha::Challenge>> {
    state.rate(
        rate::ALTCHA_CHALLENGE_IP,
        &ClientOrigin::from_headers(&headers).rate_key(),
    )?;
    state
        .run(move |state| {
            let secret = data_encoding::HEXLOWER
                .encode(&state.keys.hmac("altcha-auth-v1", b"signup-and-login"));
            let challenge = create_challenge(CreateChallengeOptions {
                algorithm: "PBKDF2/SHA-256".to_owned(),
                cost: if cfg!(test) { 1 } else { 5_000 },
                data: Some(std::collections::BTreeMap::from([(
                    "purpose".to_owned(),
                    serde_json::Value::String("auth".to_owned()),
                )])),
                expires_at: Some(now_ms() / 1000 + 300),
                hmac_signature_secret: Some(secret),
                ..Default::default()
            })
            .map_err(|error| ApiErr::internal("altcha challenge", error))?;
            Ok(Json(challenge))
        })
        .await
}

fn verify_auth_altcha(state: &AppState, encoded: &str) -> ApiResult<String> {
    if encoded.len() > 16 * 1024 {
        return Err(ApiErr::bad_request("The bot check response is too large."));
    }
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(encoded.as_bytes()))
        .map_err(|_| ApiErr::bad_request("Complete the bot check and try again."))?;
    let payload: Payload = serde_json::from_slice(&decoded)
        .map_err(|_| ApiErr::bad_request("Complete the bot check and try again."))?;
    if payload
        .challenge
        .parameters
        .data
        .as_ref()
        .and_then(|data| data.get("purpose"))
        .and_then(serde_json::Value::as_str)
        != Some("auth")
    {
        return Err(ApiErr::bad_request("Complete the bot check and try again."));
    }
    let signature = payload
        .challenge
        .signature
        .clone()
        .ok_or_else(|| ApiErr::bad_request("Complete the bot check and try again."))?;
    let secret =
        data_encoding::HEXLOWER.encode(&state.keys.hmac("altcha-auth-v1", b"signup-and-login"));
    let verified = verify_solution(VerifySolutionOptions::new(
        &payload.challenge,
        &payload.solution,
        secret,
    ))
    .map_err(|_| ApiErr::bad_request("Complete the bot check and try again."))?;
    if !verified.verified {
        return Err(ApiErr::bad_request("Complete the bot check and try again."));
    }
    Ok(signature)
}

fn admin_gate(state: &AppState, auth: &WebAuth) -> ApiResult<()> {
    let enrolled = state
        .registry()
        .twofa(&auth.account.account_id)?
        .and_then(|factor| factor.0)
        .as_deref()
        == Some("totp");
    auth.require_admin_totp(enrolled)
}

fn admin_target(actor: &WebAuth, target: &AccountRow) -> ApiResult<()> {
    if target.role == crate::db::registry::Role::Owner {
        return Err(ApiErr::new(
            StatusCode::FORBIDDEN,
            "owner_cli_only",
            "Owner accounts can only be managed from the CLI.",
        ));
    }
    if !actor.account.is_owner() && target.role != crate::db::registry::Role::User {
        return Err(ApiErr::new(
            StatusCode::FORBIDDEN,
            "owner_required",
            "Only owners can manage administrators.",
        ));
    }
    Ok(())
}

fn admin_target_settings(actor: &WebAuth, target: &AccountRow) -> ApiResult<()> {
    if actor.account.account_id == target.account_id
        && target.role == crate::db::registry::Role::Admin
    {
        return Ok(());
    }
    admin_target(actor, target)
}

fn admin_account_json(account: AccountRow) -> serde_json::Value {
    serde_json::json!({
        "accountId": account.account_id, "email": account.email,
        "state": account.state.as_str(), "role": account.role.as_str(),
        "createdAtMs": account.created_at_ms, "usageBytes": account.usage_bytes,
        "quotaBytes": account.effective_quota(), "maxVaults": account.max_vaults,
        "collectorAllowed": account.effective_collector_allowed(),
        "syncAllowed": account.sync_allowed,
        "signupMessage": account.signup_message
    })
}

async fn admin_accounts(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let accounts = state.registry().list_accounts(None)?;
            Ok(Json(accounts.into_iter().map(admin_account_json).collect()))
        })
        .await
}

async fn admin_account(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let id: AccountId = id
                .parse()
                .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
            let target = state
                .registry()
                .account(&id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            Ok(Json(admin_account_json(target)))
        })
        .await
}

async fn admin_approve(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let email = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let id: AccountId = id
                .parse()
                .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
            let target = state
                .registry()
                .account(&id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            if target.state != AccountState::Pending {
                return Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    "account_state",
                    "Only pending accounts can be approved.",
                ));
            }
            if !state.approve_account(&id, &auth.token.token_id)? {
                return Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    "account_state",
                    "Account could not be approved.",
                ));
            }
            Ok(target.email)
        })
        .await?;
    state.send_email_later(
        email,
        mail::access_decided(true, None),
        format!("approved-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_suspend(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    admin_set_state(state, auth, id, AccountState::Suspended, "suspend").await
}

async fn admin_resume(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    admin_set_state(state, auth, id, AccountState::Active, "resume").await
}

async fn admin_set_state(
    state: Shared,
    auth: WebAuth,
    id: String,
    next: AccountState,
    action: &'static str,
) -> ApiResult<StatusCode> {
    let account_id: AccountId = id
        .parse()
        .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
    let lock_account = account_id.to_string();
    let result = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let target = state
                .registry()
                .account(&account_id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            let allowed_transition = match action {
                "suspend" => target.state == AccountState::Active,
                "resume" => target.state == AccountState::Suspended,
                _ => false,
            };
            if !allowed_transition {
                return Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    "account_state",
                    "This account cannot make that state transition.",
                ));
            }
            if !state.registry().set_state(&account_id, next)? {
                return Err(ApiErr::not_found("account_not_found", "Account not found."));
            }
            state
                .registry()
                .audit(&auth.token.token_id, action, Some(&account_id), now_ms())?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await?;
    if next == AccountState::Suspended {
        crate::routes::v1::lock_collector_account(&state, &lock_account).await;
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminRoleRequest {
    role: String,
}

async fn admin_role(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
    Json(body): Json<AdminRoleRequest>,
) -> ApiResult<StatusCode> {
    state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let id: AccountId = id
                .parse()
                .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
            let target = state
                .registry()
                .account(&id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            let role = crate::db::registry::Role::parse(&body.role)
                .map_err(|_| ApiErr::bad_request("role must be user or admin."))?;
            if role == crate::db::registry::Role::Owner
                || (role == crate::db::registry::Role::Admin && !auth.account.is_owner())
            {
                return Err(ApiErr::new(
                    StatusCode::FORBIDDEN,
                    "owner_required",
                    "Only owners can grant or revoke administrator access.",
                ));
            }
            state.registry().set_role(&id, role)?;
            state
                .registry()
                .audit(&auth.token.token_id, "role-change", Some(&id), now_ms())?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminSyncRequest {
    allowed: bool,
    confirm_email: Option<String>,
}

async fn admin_sync(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
    Json(body): Json<AdminSyncRequest>,
) -> ApiResult<StatusCode> {
    let notify = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let id: AccountId = id
                .parse()
                .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
            let target = state
                .registry()
                .account(&id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target_settings(&auth, &target)?;
            if !body.allowed {
                if body.confirm_email.as_deref() != Some(target.email.as_str()) {
                    return Err(ApiErr::bad_request("Type the account email to confirm."));
                }
                state.forbid_sync(&id, &auth.token.token_id)?;
            } else {
                state.allow_sync(&id, &auth.token.token_id)?;
            }
            Ok(if body.allowed {
                None
            } else {
                Some(target.email)
            })
        })
        .await?;
    if let Some(email) = notify {
        state.send_email_later(
            email,
            mail::sync_disabled(),
            format!("sync-disabled-{}", new_secret()),
        );
        state.kick_deletions();
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AdminDecisionRequest {
    note: Option<String>,
}

async fn admin_deny(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
    Json(body): Json<AdminDecisionRequest>,
) -> ApiResult<StatusCode> {
    if body
        .note
        .as_ref()
        .is_some_and(|note| note.chars().count() > 1000)
    {
        return Err(ApiErr::bad_request(
            "The note must be at most 1000 characters.",
        ));
    }
    let parsed_id: AccountId = id
        .parse()
        .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
    let lock_account = parsed_id.to_string();
    let (email, note) = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let target = state
                .registry()
                .account(&parsed_id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            if target.state != AccountState::Pending {
                return Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    "account_state",
                    "Only pending accounts can be denied.",
                ));
            }
            state
                .registry()
                .audit(&auth.token.token_id, "deny", Some(&parsed_id), now_ms())?;
            state.delete_account(&parsed_id)?;
            Ok((target.email, body.note))
        })
        .await?;
    crate::routes::v1::lock_collector_account(&state, &lock_account).await;
    state.kick_deletions();
    state.send_email_later(
        email,
        mail::access_decided(false, note.as_deref()),
        format!("denied-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_delete_account(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let parsed_id: AccountId = id
        .parse()
        .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
    let lock_account = parsed_id.to_string();
    let email = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let target = state
                .registry()
                .account(&parsed_id)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            state.registry().audit(
                &auth.token.token_id,
                "admin-delete",
                Some(&parsed_id),
                now_ms(),
            )?;
            state.delete_account(&parsed_id)?;
            Ok(target.email)
        })
        .await?;
    crate::routes::v1::lock_collector_account(&state, &lock_account).await;
    state.kick_deletions();
    state.send_email_later(
        email,
        mail::data_deleted(true),
        format!("admin-deleted-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_reset_2fa(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let email = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let parsed: AccountId = id
                .parse()
                .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
            let target = state
                .registry()
                .account(&parsed)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target(&auth, &target)?;
            let registry = state.registry();
            registry.reset_twofa(&parsed)?;
            for token in registry.tokens_for(&parsed)? {
                if token.kind == "session" {
                    registry.revoke_token(
                        &parsed,
                        &token.token_id,
                        &auth.token.token_id,
                        now_ms(),
                    )?;
                }
            }
            registry.audit(&auth.token.token_id, "reset-2fa", Some(&parsed), now_ms())?;
            Ok(target.email)
        })
        .await?;
    state.send_email_later(email, mail::notice("Your two-factor authentication was reset", "An administrator reset two-factor authentication. You will need to enroll a method the next time you sign in."), format!("reset-2fa-{}", new_secret()));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminLimitsRequest {
    quota: Option<String>,
    max_vaults: Option<u32>,
}

async fn admin_limits(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
    Json(body): Json<AdminLimitsRequest>,
) -> ApiResult<StatusCode> {
    let parsed: AccountId = id
        .parse()
        .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
    let has_quota = body.quota.is_some();
    let quota = match body.quota {
        Some(value) => Some(crate::config::parse_size(&value).map_err(ApiErr::bad_request)?),
        None => None,
    };
    if has_quota {
        crate::config::validate_quota(quota.flatten()).map_err(ApiErr::bad_request)?;
    }
    if body.max_vaults.is_some_and(|n| n == 0 || n > 1000) {
        return Err(ApiErr::bad_request("maxVaults must be between 1 and 1000."));
    }
    state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let target = state
                .registry()
                .account(&parsed)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target_settings(&auth, &target)?;
            let registry = state.registry();
            if let Some(quota) = quota {
                registry.set_quota(&parsed, quota)?;
            }
            if let Some(max_vaults) = body.max_vaults {
                registry.set_max_vaults(&parsed, max_vaults)?;
            }
            registry.audit(
                &auth.token.token_id,
                "account-limits",
                Some(&parsed),
                now_ms(),
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

#[derive(Deserialize)]
struct AdminCollectorRequest {
    allowed: bool,
}

async fn admin_collector(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(id): Path<String>,
    Json(body): Json<AdminCollectorRequest>,
) -> ApiResult<StatusCode> {
    let parsed: AccountId = id
        .parse()
        .map_err(|_| ApiErr::not_found("account_not_found", "Account not found."))?;
    let lock_account = parsed.to_string();
    let allowed = body.allowed;
    let result = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let target = state
                .registry()
                .account(&parsed)?
                .ok_or_else(|| ApiErr::not_found("account_not_found", "Account not found."))?;
            admin_target_settings(&auth, &target)?;
            state
                .registry()
                .set_collector_allowed(&parsed, body.allowed)?;
            state.registry().audit(
                &auth.token.token_id,
                "collector-access",
                Some(&parsed),
                now_ms(),
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await?;
    if !allowed {
        crate::routes::v1::lock_collector_account(&state, &lock_account).await;
    }
    Ok(result)
}

#[derive(Deserialize)]
struct AdminInviteRequest {
    email: String,
}

async fn admin_invite(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(body): Json<AdminInviteRequest>,
) -> ApiResult<StatusCode> {
    let email = normalize_email(&body.email)?;
    let (target_email, link) = state
        .run(move |state| {
            admin_gate(state, &auth)?;
            if state.registry().account_by_email(&email)?.is_some() {
                return Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    "account_exists",
                    "An account with this email already exists.",
                ));
            }
            let id = AccountId::random().map_err(|e| ApiErr::internal("rng", e))?;
            let quota = effective_default_quota(state);
            let collector_default = effective_collector_default(state);
            let registry = state.registry();
            registry.create_account(&id, &email, AccountState::Unverified, quota, now_ms())?;
            registry.set_collector_allowed(&id, collector_default)?;
            registry.audit(&auth.token.token_id, "invite", Some(&id), now_ms())?;
            drop(registry);
            let invite = store_token(state, &id, "invite", INVITE_TTL_MS, None)?;
            Ok((email, web_link(state, "invite", &invite)))
        })
        .await?;
    state
        .send_email(
            &target_email,
            mail::invite(&link),
            format!("invite-{}", new_secret()),
        )
        .await?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) fn effective_registration(
    state: &AppState,
) -> vrcx_0_nanashi_website_protocol::api::Registration {
    match state
        .registry()
        .setting("registration")
        .ok()
        .flatten()
        .as_deref()
    {
        Some("request") => vrcx_0_nanashi_website_protocol::api::Registration::Request,
        Some("closed") => vrcx_0_nanashi_website_protocol::api::Registration::Closed,
        _ => state.config.registration,
    }
}

pub(crate) fn effective_default_quota(state: &AppState) -> Option<u64> {
    match state.registry().setting("default_quota").ok().flatten() {
        Some(value) => crate::config::parse_size(&value)
            .ok()
            .unwrap_or(state.config.default_quota_bytes),
        None => state.config.default_quota_bytes,
    }
}

pub(crate) fn effective_collector_default(state: &AppState) -> bool {
    state
        .registry()
        .setting("collector_default_allowed")
        .ok()
        .flatten()
        .map(|value| value == "true")
        .unwrap_or(state.config.collector_default_allowed)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminSettingsRequest {
    registration: Option<String>,
    default_quota: Option<String>,
    collector_default_allowed: Option<bool>,
}

async fn admin_settings(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<serde_json::Value>> {
    state.run(move |state| {
        admin_gate(state, &auth)?;
        let registration = effective_registration(state);
        let quota = effective_default_quota(state);
        Ok(Json(serde_json::json!({"registration": registration, "defaultQuota": quota, "collectorDefaultAllowed": effective_collector_default(state), "websiteOrigins": state.config.web_origins, "apiOrigin": state.config.api_origin, "commit": state.config.commit})))
    }).await
}

async fn admin_update_settings(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(body): Json<AdminSettingsRequest>,
) -> ApiResult<StatusCode> {
    if body
        .registration
        .as_deref()
        .is_some_and(|v| v != "request" && v != "closed")
    {
        return Err(ApiErr::bad_request(
            "registration must be request or closed.",
        ));
    }
    let quota = match body.default_quota.as_deref() {
        Some(value) => {
            let parsed = crate::config::parse_size(value).map_err(ApiErr::bad_request)?;
            crate::config::validate_quota(parsed).map_err(ApiErr::bad_request)?;
            Some(parsed)
        }
        None => None,
    };
    state
        .run(move |state| {
            admin_gate(state, &auth)?;
            let registry = state.registry();
            if let Some(registration) = body.registration {
                registry.set_setting("registration", &registration)?;
            }
            if let Some(quota) = quota {
                registry.set_setting("default_quota", &crate::config::format_size(quota))?;
            }
            if let Some(allowed) = body.collector_default_allowed {
                registry.set_setting(
                    "collector_default_allowed",
                    if allowed { "true" } else { "false" },
                )?;
            }
            registry.audit(&auth.token.token_id, "settings-change", None, now_ms())?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn admin_audit(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    state.run(move |state| {
        admin_gate(state, &auth)?;
        let entries = state.registry().audit_entries(None)?;
        Ok(Json(entries.into_iter().map(|(actor, action, target, at_ms)| serde_json::json!({"actor": actor, "action": action, "targetAccount": target, "atMs": at_ms})).collect()))
    }).await
}

fn new_secret() -> String {
    b64::encode(&random_bytes::<32>())
}

fn token_hash(state: &AppState, token: &str) -> [u8; 32] {
    state.keys.hmac(AUTH_TOKEN_PURPOSE, token.as_bytes())
}

fn store_token(
    state: &AppState,
    account: &AccountId,
    purpose: &str,
    ttl_ms: i64,
    data: Option<&str>,
) -> ApiResult<String> {
    let token = new_secret();
    state.registry().insert_auth_token(
        &token_hash(state, &token),
        account,
        purpose,
        now_ms() + ttl_ms,
        data,
    )?;
    Ok(token)
}

fn check_token(
    state: &AppState,
    token: &str,
    purpose: &str,
    max_attempts: i64,
) -> ApiResult<(AccountRow, Option<String>)> {
    let invalid = || {
        ApiErr::new(
            StatusCode::UNAUTHORIZED,
            "invalid_or_expired",
            "This link or step has expired. Start again.",
        )
    };
    let registry = state.registry();
    let (account_id, data) = registry
        .use_auth_token(&token_hash(state, token), purpose, now_ms(), max_attempts)?
        .ok_or_else(invalid)?;
    let account = registry.account(&account_id)?.ok_or_else(invalid)?;
    Ok((account, data))
}

fn finish_token(state: &AppState, token: &str) -> ApiResult<()> {
    state
        .registry()
        .delete_auth_token(&token_hash(state, token))?;
    Ok(())
}

fn web_link(state: &AppState, path: &str, token: &str) -> String {
    let origin = state
        .config
        .web_origins
        .first()
        .cloned()
        .unwrap_or_default();
    format!("{origin}/{path}#{token}")
}

fn browser_label(headers: &HeaderMap) -> String {
    let agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let browser = ["Firefox", "Edg", "OPR", "Chrome", "Safari"]
        .into_iter()
        .find(|name| agent.contains(name))
        .map(|name| match name {
            "Edg" => "Edge",
            "OPR" => "Opera",
            other => other,
        })
        .unwrap_or("Browser");
    let os = [
        ("Windows", "Windows"),
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iPadOS"),
        ("Mac OS", "macOS"),
        ("Linux", "Linux"),
    ]
    .into_iter()
    .find(|(needle, _)| agent.contains(needle))
    .map(|(_, os)| os)
    .unwrap_or("unknown OS");
    format!("{browser} on {os}")
}

pub(crate) fn issue_session(
    state: &AppState,
    account: &AccountRow,
    label: &str,
) -> ApiResult<String> {
    let (full, parts) =
        token::generate(TokenKind::Session).map_err(|e| ApiErr::internal("rng", e))?;
    let now = now_ms();
    state.registry().insert_token(&NewToken {
        token_id: &parts.id,
        account_id: &account.account_id,
        kind: "session",
        client_kind: ClientKind::WebSession,
        secret_hmac: &state.keys.hmac(TOKEN_HMAC_PURPOSE, &parts.secret),
        scopes: ALL_SCOPES,
        label,
        client_version: None,
        now_ms: now,
        expires_at_ms: Some(now + SESSION_MAX_MS),
        idle_timeout_ms: Some(SESSION_IDLE_MS),
    })?;
    Ok(full.to_string())
}

fn email_code() -> String {
    loop {
        let value = u32::from_le_bytes(random_bytes::<4>());
        if value < 4_294_000_000 {
            return format!("{:06}", value % 1_000_000);
        }
    }
}

pub(crate) async fn send_email_code(
    state: &Shared,
    account: &AccountRow,
    purpose: &'static str,
) -> ApiResult<()> {
    if purpose == "login" {
        state.rate(rate::LOGIN_EMAIL_CODE_SEND, account.account_id.as_str())?;
    } else {
        state.rate(rate::EMAIL_SEND, account.account_id.as_str())?;
    }
    let code = email_code();
    let account_id = account.account_id.clone();
    let code_for_db = code.clone();
    state
        .run(move |state| {
            let hash = state.keys.hmac(EMAIL_CODE_PURPOSE, code_for_db.as_bytes());
            state
                .registry()
                .set_email_code(&account_id, purpose, &hash, now_ms() + CODE_TTL_MS)?;
            Ok(())
        })
        .await?;
    let key = format!(
        "code-{}-{}",
        account.account_id,
        b64::encode(&random_bytes::<8>())
    );
    state
        .send_email(&account.email, mail::email_code(&code), key)
        .await
}

fn check_email_code(
    state: &AppState,
    account: &AccountRow,
    purpose: &str,
    code: &str,
) -> ApiResult<bool> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let hash = state.keys.hmac(EMAIL_CODE_PURPOSE, code.as_bytes());
    Ok(state
        .registry()
        .use_email_code(&account.account_id, purpose, &hash, now_ms())?)
}

fn wrong_code() -> ApiErr {
    ApiErr::new(
        StatusCode::UNAUTHORIZED,
        codes::UNAUTHORIZED,
        "Code not accepted.",
    )
}

fn bad_credentials() -> ApiErr {
    ApiErr::new(
        StatusCode::UNAUTHORIZED,
        codes::UNAUTHORIZED,
        "Email or password is wrong.",
    )
}

fn normalize_email(email: &str) -> ApiResult<String> {
    let email = email.trim();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        })
        && !email.contains(|c: char| {
            c.is_whitespace() || c.is_control() || matches!(c, ',' | ';' | '<' | '>')
        });
    if valid {
        Ok(email.to_owned())
    } else {
        Err(ApiErr::bad_request("Enter a valid email address."))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignupRequest {
    email: String,
    password: String,
    altcha: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    invite_token: Option<String>,
}

async fn signup(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<SignupRequest>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    state.rate(
        rate::AUTH_START,
        &ClientOrigin::from_headers(&headers).rate_key(),
    )?;
    let origin = ClientOrigin::from_headers(&headers).rate_key();
    state
        .limiter
        .check(rate::SIGNUP_IP, &origin, now_ms())
        .map_err(ApiErr::rate_limited)?;
    let captcha_signature = verify_auth_altcha(&state, &request.altcha)?;
    state.rate(rate::ALTCHA_USED, &format!("auth:{captcha_signature}"))?;
    let email = normalize_email(&request.email)?;
    passwords::check(&request.password).map_err(|p| ApiErr::bad_request(p.message()))?;
    if request.message.chars().count() > 2000 {
        return Err(ApiErr::bad_request(
            "The message can be at most 2000 characters.",
        ));
    }
    state.rate(rate::SIGNUP_IP, &origin)?;
    state.rate(rate::SIGNUP_EMAIL, &email)?;
    let hash = passwords::hash(&request.password);
    let invite = request.invite_token.clone();
    let outcome = state
        .run(move |state| {
            if let Some(invite) = invite {
                let (account, _) = check_token(state, &invite, "invite", 3)?;
                if !account.email.eq_ignore_ascii_case(&email)
                    || account.state != AccountState::Unverified
                {
                    return Err(ApiErr::bad_request(
                        "This invite is for a different email address.",
                    ));
                }
                finish_token(state, &invite)?;
                let registry = state.registry();
                registry.set_password_hash(&account.account_id, &hash)?;
                registry.set_email_verified(&account.account_id, now_ms())?;
                drop(registry);
                let challenge = store_token(
                    state,
                    &account.account_id,
                    "enroll",
                    CHALLENGE_TTL_MS,
                    Some("invited"),
                )?;
                return Ok(Signup::Invited(challenge));
            }
            if effective_registration(state)
                == vrcx_0_nanashi_website_protocol::api::Registration::Closed
            {
                return Err(ApiErr::feature_disabled(
                    "Sign-up is by invitation only on this server.",
                ));
            }
            let quota = effective_default_quota(state);
            let collector_default = effective_collector_default(state);
            let registry = state.registry();
            if let Some(existing) = registry.account_by_email(&email)? {
                return Ok(match existing.state {
                    AccountState::Unverified => {
                        drop(registry);
                        let token =
                            store_token(state, &existing.account_id, "verify", LINK_TTL_MS, None)?;
                        Signup::Verify(existing.email, token)
                    }
                    _ => Signup::Exists(existing.email),
                });
            }
            let account_id = AccountId::random().map_err(|e| ApiErr::internal("rng", e))?;
            registry.create_account(
                &account_id,
                &email,
                AccountState::Unverified,
                quota,
                now_ms(),
            )?;
            registry.set_collector_allowed(&account_id, collector_default)?;
            registry.set_password_hash(&account_id, &hash)?;
            registry.set_signup_message(&account_id, request.message.trim())?;
            drop(registry);
            let token = store_token(state, &account_id, "verify", LINK_TTL_MS, None)?;
            Ok(Signup::Verify(email, token))
        })
        .await?;
    match outcome {
        Signup::Verify(email, token) => {
            let link = web_link(&state, "verify", &token);
            state
                .send_email(
                    &email,
                    mail::verify_address(&link),
                    format!("verify-{token}"),
                )
                .await?;
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Signup::Exists(email) => {
            state.send_email_later(
                email,
                mail::signup_existing_account(),
                format!("exists-{}", new_secret()),
            );
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Signup::Invited(challenge) => Ok(Json(ChallengeResponse {
            challenge,
            next: "enroll",
            methods: vec!["totp", "email"],
        })
        .into_response()),
    }
}

enum Signup {
    Verify(String, String),
    Exists(String),
    Invited(String),
}

#[derive(Deserialize)]
struct TokenRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge: String,
    next: &'static str,
    methods: Vec<&'static str>,
}

async fn verify(
    State(state): State<Shared>,
    Json(request): Json<TokenRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    state
        .run(move |state| {
            let (account, _) = check_token(state, &request.token, "verify", 5)?;
            finish_token(state, &request.token)?;
            state
                .registry()
                .set_email_verified(&account.account_id, now_ms())?;
            let challenge =
                store_token(state, &account.account_id, "enroll", CHALLENGE_TTL_MS, None)?;
            Ok(Json(ChallengeResponse {
                challenge,
                next: "enroll",
                methods: vec!["totp", "email"],
            }))
        })
        .await
}

#[derive(Deserialize)]
struct ResendVerificationRequest {
    challenge: String,
}

async fn resend_verification(
    State(state): State<Shared>,
    Json(request): Json<ResendVerificationRequest>,
) -> ApiResult<StatusCode> {
    let challenge = request.challenge;
    let account = state
        .run(move |state| {
            let (account, _) = check_token(state, &challenge, "verify-resend", 5)?;
            if account.state != AccountState::Unverified {
                return Err(ApiErr::bad_request("This account is already verified."));
            }
            Ok(account)
        })
        .await?;
    state.rate(rate::VERIFY_RESEND, account.account_id.as_str())?;
    let account_id = account.account_id.clone();
    let token = state
        .run(move |state| store_token(state, &account_id, "verify", LINK_TTL_MS, None))
        .await?;
    let link = web_link(&state, "verify", &token);
    state
        .send_email(
            &account.email,
            mail::verify_address(&link),
            format!("verify-{token}"),
        )
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct ChallengeRequest {
    challenge: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpSetup {
    secret: String,
    uri: String,
}

fn totp_context(account: &AccountId) -> String {
    format!("totp:{account}")
}

fn start_totp(state: &AppState, account: &AccountRow) -> ApiResult<TotpSetup> {
    let secret = Zeroizing::new(random_bytes::<20>());
    let wrapped = state
        .keys
        .wrap(&totp_context(&account.account_id), secret.as_slice());
    state
        .registry()
        .set_totp_pending(&account.account_id, &wrapped)?;
    let encoded = data_encoding::BASE32_NOPAD.encode(secret.as_slice());
    let issuer = "VRCX-0-Nanashi RemoteSync";
    let uri = format!(
        "otpauth://totp/{}:{}?secret={encoded}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent(issuer),
        percent(&account.email),
        percent(issuer)
    );
    Ok(TotpSetup {
        secret: encoded,
        uri,
    })
}

fn percent(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn confirm_totp(state: &AppState, account: &AccountRow, code: &str) -> ApiResult<bool> {
    let Some(wrapped) = state.registry().totp_pending(&account.account_id)? else {
        return Ok(false);
    };
    let secret = state
        .keys
        .unwrap(&totp_context(&account.account_id), &wrapped)
        .map_err(|e| ApiErr::internal("totp", e))?;
    match totp::verify(&secret, code, now_ms(), 0) {
        Some(step) => Ok(state
            .registry()
            .activate_pending_totp(&account.account_id, step)?),
        None => Ok(false),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrolledResponse {
    session: String,
    recovery_codes: Vec<String>,
    state: &'static str,
}

fn finish_enrollment(
    state: &AppState,
    account: &AccountRow,
    invited: bool,
    label: &str,
) -> ApiResult<EnrolledResponse> {
    let (plain, hashes) = recovery::generate(&state.keys);
    let registry = state.registry();
    registry.replace_recovery_codes(&account.account_id, &hashes)?;
    let new_state = match account.state {
        AccountState::Unverified if invited => AccountState::Active,
        AccountState::Unverified => AccountState::Pending,
        other => other,
    };
    registry.set_state(&account.account_id, new_state)?;
    drop(registry);
    let account = state
        .registry()
        .account(&account.account_id)?
        .ok_or_else(|| ApiErr::internal("enroll", "account vanished"))?;
    let session = issue_session(state, &account, label)?;
    Ok(EnrolledResponse {
        session,
        recovery_codes: plain,
        state: new_state.as_str(),
    })
}

async fn enroll_totp_start(
    State(state): State<Shared>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Json<TotpSetup>> {
    state
        .run(move |state| {
            let (account, _) = check_token(state, &request.challenge, "enroll", 10)?;
            Ok(Json(start_totp(state, &account)?))
        })
        .await
}

#[derive(Deserialize)]
struct ChallengeCode {
    challenge: String,
    code: String,
}

async fn enroll_totp_confirm(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<ChallengeCode>,
) -> ApiResult<Json<EnrolledResponse>> {
    let label = browser_label(&headers);
    state
        .run(move |state| {
            let (account, data) = check_token(state, &request.challenge, "enroll", 10)?;
            if !confirm_totp(state, &account, &request.code)? {
                return Err(wrong_code());
            }
            finish_token(state, &request.challenge)?;
            Ok(Json(finish_enrollment(
                state,
                &account,
                data.as_deref() == Some("invited"),
                &label,
            )?))
        })
        .await
}

async fn enroll_email_start(
    State(state): State<Shared>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<StatusCode> {
    let account = state
        .run(move |state| Ok(check_token(state, &request.challenge, "enroll", 10)?.0))
        .await?;
    send_email_code(&state, &account, "enroll").await?;
    Ok(StatusCode::ACCEPTED)
}

async fn enroll_email_confirm(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<ChallengeCode>,
) -> ApiResult<Json<EnrolledResponse>> {
    let label = browser_label(&headers);
    state
        .run(move |state| {
            let (account, data) = check_token(state, &request.challenge, "enroll", 10)?;
            if !check_email_code(state, &account, "enroll", &request.code)? {
                return Err(wrong_code());
            }
            state.registry().set_twofa_email(&account.account_id)?;
            finish_token(state, &request.challenge)?;
            Ok(Json(finish_enrollment(
                state,
                &account,
                data.as_deref() == Some("invited"),
                &label,
            )?))
        })
        .await
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    altcha: String,
}

fn methods_for(state: &AppState, account: &AccountRow) -> ApiResult<Option<Vec<&'static str>>> {
    let method = state
        .registry()
        .twofa(&account.account_id)?
        .and_then(|(method, _, _)| method);
    Ok(match method.as_deref() {
        Some("totp") => Some(vec!["totp", "recovery"]),
        Some("email") => Some(vec!["email", "recovery"]),
        _ => None,
    })
}

async fn login(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    state.rate(
        rate::AUTH_START,
        &ClientOrigin::from_headers(&headers).rate_key(),
    )?;
    let origin = ClientOrigin::from_headers(&headers).rate_key();
    state.rate(rate::LOGIN_IP, &origin)?;
    let captcha_signature = verify_auth_altcha(&state, &request.altcha)?;
    state.rate(rate::ALTCHA_USED, &format!("auth:{captcha_signature}"))?;
    let email = request.email.trim().to_ascii_lowercase();
    state.rate(rate::LOGIN_EMAIL, &email)?;
    state
        .limiter
        .check(rate::LOGIN_FAILURE_IP, &origin, now_ms())
        .map_err(ApiErr::rate_limited)?;
    state
        .limiter
        .check(rate::LOGIN_FAILURE_EMAIL, &email, now_ms())
        .map_err(ApiErr::rate_limited)?;
    state
        .run(move |state| {
            let account = state.registry().account_by_email(&email)?;
            let stored = match &account {
                Some(a) => state.registry().password_hash(&a.account_id)?,
                None => None,
            };
            let (Some(account), Some(stored)) = (account, stored) else {
                passwords::verify_dummy(&request.password);
                state
                    .limiter
                    .fail(rate::LOGIN_FAILURE_IP, &origin, now_ms());
                state
                    .limiter
                    .fail(rate::LOGIN_FAILURE_EMAIL, &email, now_ms());
                return Err(bad_credentials());
            };
            if !passwords::verify(&stored, &request.password) {
                state
                    .limiter
                    .fail(rate::LOGIN_FAILURE_IP, &origin, now_ms());
                state
                    .limiter
                    .fail(rate::LOGIN_FAILURE_EMAIL, &email, now_ms());
                return Err(bad_credentials());
            }
            if account.state == AccountState::Unverified {
                let challenge = store_token(
                    state,
                    &account.account_id,
                    "verify-resend",
                    CHALLENGE_TTL_MS,
                    None,
                )?;
                return Ok(Json(ChallengeResponse {
                    challenge,
                    next: "verify-email",
                    methods: Vec::new(),
                }));
            }
            match methods_for(state, &account)? {
                Some(methods) => {
                    let challenge =
                        store_token(state, &account.account_id, "login", CHALLENGE_TTL_MS, None)?;
                    Ok(Json(ChallengeResponse {
                        challenge,
                        next: "2fa",
                        methods,
                    }))
                }
                None => {
                    let challenge =
                        store_token(state, &account.account_id, "enroll", CHALLENGE_TTL_MS, None)?;
                    Ok(Json(ChallengeResponse {
                        challenge,
                        next: "enroll",
                        methods: vec!["totp", "email"],
                    }))
                }
            }
        })
        .await
}

async fn login_email_code(
    State(state): State<Shared>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<StatusCode> {
    let account = state
        .run(move |state| {
            let (account, _) = check_token(state, &request.challenge, "login", 10)
                .or_else(|_| check_token(state, &request.challenge, "reset-2fa", 10))?;
            Ok(account)
        })
        .await?;
    send_email_code(&state, &account, "login").await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct SecondFactorRequest {
    challenge: String,
    method: ReauthMethod,
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    session: String,
    state: &'static str,
}

pub(crate) fn second_factor(
    state: &Shared,
    account: &AccountRow,
    method: ReauthMethod,
    code: &str,
    email_purpose: &str,
) -> ApiResult<bool> {
    let normalized_code = code
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let ok = match method {
        ReauthMethod::Email => check_email_code(state, account, email_purpose, &normalized_code)?,
        other => check_second_factor(state, account, other, &normalized_code, now_ms())?,
    };
    if ok && method == ReauthMethod::Recovery {
        let left = state.registry().recovery_codes_left(&account.account_id)?;
        state.send_email_later(
            account.email.clone(),
            mail::recovery_code_used(left),
            format!("recovery-{}", new_secret()),
        );
    }
    Ok(ok)
}

async fn login_second_factor(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<SecondFactorRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let label = browser_label(&headers);
    let session_label = label.clone();
    let origin = ClientOrigin::from_headers(&headers);
    let shared = state.clone();
    let (account, session, totp_used) = state
        .run(move |state| {
            state.rate(rate::REAUTH, &format!("challenge:{}", request.challenge))?;
            let (account, data, purpose) = match check_token(state, &request.challenge, "login", 10)
            {
                Ok((account, data)) => (account, data, "login"),
                Err(_) => {
                    let (account, data) = check_token(state, &request.challenge, "reset-2fa", 10)?;
                    (account, data, "reset-2fa")
                }
            };
            if !second_factor(&shared, &account, request.method, &request.code, "login")? {
                return Err(wrong_code());
            }
            finish_token(state, &request.challenge)?;
            if purpose == "reset-2fa" {
                let hash = data.ok_or_else(|| ApiErr::internal("reset", "missing password"))?;
                let registry = state.registry();
                registry.set_password_hash(&account.account_id, &hash)?;
                for token in registry.tokens_for(&account.account_id)? {
                    if token.kind == "session" {
                        registry.revoke_token(
                            &account.account_id,
                            &token.token_id,
                            "password-reset",
                            now_ms(),
                        )?;
                    }
                }
            }
            let session = issue_session(state, &account, &session_label)?;
            Ok((account, session, request.method == ReauthMethod::Totp))
        })
        .await?;
    if totp_used {
        let session_id = token::parse(&session, TokenKind::Session)
            .map_err(|e| ApiErr::internal("session", e))?
            .id;
        state
            .run(move |state| {
                Ok(state
                    .registry()
                    .set_recent_totp(&session_id, now_ms() + RECENT_AUTH_MS)?)
            })
            .await?;
    }
    let place = [origin.city.as_deref(), origin.country.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
    state.send_email_later(
        account.email.clone(),
        mail::new_sign_in(
            &label,
            origin.ip.as_deref(),
            (!place.is_empty()).then_some(place.as_str()),
        ),
        format!("signin-{}", new_secret()),
    );
    Ok(Json(SessionResponse {
        session,
        state: account.state.as_str(),
    }))
}

#[derive(Deserialize)]
struct EmailRequest {
    email: String,
}

async fn reset_start(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<EmailRequest>,
) -> ApiResult<StatusCode> {
    state.rate(
        rate::AUTH_START,
        &ClientOrigin::from_headers(&headers).rate_key(),
    )?;
    let email = request.email.trim().to_owned();
    let target = state
        .run(move |state| {
            let Some(account) = state.registry().account_by_email(&email)? else {
                return Ok(None);
            };
            if account.state == AccountState::Unverified {
                return Ok(None);
            }
            let token = store_token(state, &account.account_id, "reset", LINK_TTL_MS, None)?;
            Ok(Some((account, token)))
        })
        .await?;
    if let Some((account, token)) = target {
        state.rate(rate::EMAIL_SEND, account.account_id.as_str())?;
        let link = web_link(&state, "reset", &token);
        state
            .send_email(
                &account.email,
                mail::password_reset(&link),
                format!("reset-{token}"),
            )
            .await?;
    }
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
struct ResetFinishRequest {
    token: String,
    password: String,
}

async fn reset_finish(
    State(state): State<Shared>,
    Json(request): Json<ResetFinishRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    passwords::check(&request.password).map_err(|p| ApiErr::bad_request(p.message()))?;
    let hash = passwords::hash(&request.password);
    state
        .run(move |state| {
            let (account, _) = check_token(state, &request.token, "reset", 5)?;
            finish_token(state, &request.token)?;
            let methods = methods_for(state, &account)?.ok_or_else(|| {
                ApiErr::new(
                    StatusCode::FORBIDDEN,
                    "twofa_missing",
                    "This account has no 2FA set up. Sign in to set it up first.",
                )
            })?;
            let challenge = store_token(
                state,
                &account.account_id,
                "reset-2fa",
                CHALLENGE_TTL_MS,
                Some(&hash),
            )?;
            Ok(Json(ChallengeResponse {
                challenge,
                next: "2fa",
                methods,
            }))
        })
        .await
}

async fn sign_out(State(state): State<Shared>, auth: WebAuth) -> ApiResult<StatusCode> {
    state
        .run(move |state| {
            state.registry().revoke_token(
                &auth.account.account_id,
                &auth.token.token_id,
                &auth.token.token_id,
                now_ms(),
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Me {
    account_id: AccountId,
    email: String,
    state: &'static str,
    role: &'static str,
    twofa_method: Option<String>,
    recovery_codes_left: i64,
    usage_bytes: u64,
    quota_bytes: Option<u64>,
    sync_allowed: bool,
    collector_allowed: bool,
    admin_available: bool,
    recent_auth_until_ms: i64,
    recent_totp_until_ms: i64,
}

async fn me(State(state): State<Shared>, auth: WebAuth) -> ApiResult<Json<Me>> {
    state
        .run(move |state| {
            let restricted = auth.account.state != AccountState::Active;
            let registry = state.registry();
            let method = registry
                .twofa(&auth.account.account_id)?
                .and_then(|(m, _, _)| m);
            let left = if restricted {
                0
            } else {
                registry.recovery_codes_left(&auth.account.account_id)?
            };
            let account = &auth.account;
            Ok(Json(Me {
                account_id: account.account_id.clone(),
                email: account.email.clone(),
                state: account.state.as_str(),
                role: if restricted {
                    "user"
                } else {
                    account.role.as_str()
                },
                admin_available: !restricted
                    && account.role.can_administer()
                    && method.as_deref() == Some("totp"),
                twofa_method: method,
                recovery_codes_left: left,
                usage_bytes: if restricted { 0 } else { account.usage_bytes },
                quota_bytes: if restricted {
                    None
                } else {
                    account.effective_quota()
                },
                sync_allowed: !restricted && account.sync_allowed,
                collector_allowed: !restricted && account.effective_collector_allowed(),
                recent_auth_until_ms: if restricted {
                    0
                } else {
                    auth.token.recent_auth_until_ms
                },
                recent_totp_until_ms: if restricted {
                    0
                } else {
                    auth.token.recent_totp_until_ms
                },
            }))
        })
        .await
}

#[derive(Deserialize)]
struct ReauthRequest {
    method: ReauthMethod,
    code: String,
}

async fn reauth(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(request): Json<ReauthRequest>,
) -> ApiResult<StatusCode> {
    state.rate(rate::REAUTH, auth.account.account_id.as_str())?;
    let shared = state.clone();
    state
        .run(move |state| {
            if !second_factor(
                &shared,
                &auth.account,
                request.method,
                &request.code,
                "reauth",
            )? {
                return Err(wrong_code());
            }
            let until = now_ms() + RECENT_AUTH_MS;
            let registry = state.registry();
            if request.method == ReauthMethod::Totp {
                registry.set_recent_totp(&auth.token.token_id, until)?;
            } else {
                registry.set_recent_auth(&auth.token.token_id, until)?;
            }
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn reauth_email_code(State(state): State<Shared>, auth: WebAuth) -> ApiResult<StatusCode> {
    send_email_code(&state, &auth.account, "reauth").await?;
    Ok(StatusCode::ACCEPTED)
}

async fn twofa_totp_start(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<TotpSetup>> {
    auth.require_recent_auth()?;
    state
        .run(move |state| Ok(Json(start_totp(state, &auth.account)?)))
        .await
}

#[derive(Deserialize)]
struct CodeRequest {
    code: String,
}

async fn twofa_totp_confirm(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(request): Json<CodeRequest>,
) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            if !confirm_totp(state, &auth.account, &request.code)? {
                return Err(wrong_code());
            }
            state.registry().audit(
                &auth.token.token_id,
                "twofa-change",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Your authenticator method was changed",
            "An authenticator app was set as the two-factor method for your account.",
        ),
        format!("twofa-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn twofa_email_start(State(state): State<Shared>, auth: WebAuth) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    send_email_code(&state, &auth.account, "change-twofa").await?;
    Ok(StatusCode::ACCEPTED)
}

async fn twofa_email_confirm(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(request): Json<CodeRequest>,
) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            if !check_email_code(state, &auth.account, "change-twofa", &request.code)? {
                return Err(wrong_code());
            }
            state.registry().set_twofa_email(&auth.account.account_id)?;
            state.registry().audit(
                &auth.token.token_id,
                "twofa-change",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Your authenticator method was changed",
            "Email codes were set as the two-factor method for your account.",
        ),
        format!("twofa-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCodes {
    recovery_codes: Vec<String>,
}

async fn regenerate_recovery_codes(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<RecoveryCodes>> {
    auth.require_recent_auth()?;
    let email = auth.account.email.clone();
    let codes = state
        .run(move |state| {
            let (plain, hashes) = recovery::generate(&state.keys);
            state
                .registry()
                .replace_recovery_codes(&auth.account.account_id, &hashes)?;
            state.registry().audit(
                &auth.token.token_id,
                "recovery-codes",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(plain)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "New recovery codes",
            "New recovery codes were generated for your account. The old ones no longer work.",
        ),
        format!("codes-{}", new_secret()),
    );
    Ok(Json(RecoveryCodes {
        recovery_codes: codes,
    }))
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}

async fn change_password(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(request): Json<PasswordRequest>,
) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    passwords::check(&request.password).map_err(|p| ApiErr::bad_request(p.message()))?;
    let hash = passwords::hash(&request.password);
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            let registry = state.registry();
            registry.set_password_hash(&auth.account.account_id, &hash)?;
            for token in registry.tokens_for(&auth.account.account_id)? {
                if token.kind == "session" && token.token_id != auth.token.token_id {
                    registry.revoke_token(
                        &auth.account.account_id,
                        &token.token_id,
                        &auth.token.token_id,
                        now_ms(),
                    )?;
                }
            }
            registry.audit(
                &auth.token.token_id,
                "password-change",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(())
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Your password was changed",
            "The password of your account was changed and your other website sessions were ended.",
        ),
        format!("password-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_account(State(state): State<Shared>, auth: WebAuth) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    if auth.account.is_owner() {
        return Err(ApiErr::new(
            StatusCode::FORBIDDEN,
            "owner_cli_only",
            "Owner accounts can only be deleted with the server CLI.",
        ));
    }
    let email = auth.account.email.clone();
    let lock_account = auth.account.account_id.to_string();
    state
        .run(move |state| {
            state
                .registry()
                .audit(&auth.token.token_id, "delete-account", None, now_ms())?;
            state.delete_account(&auth.account.account_id)
        })
        .await?;
    crate::routes::v1::lock_collector_account(&state, &lock_account).await;
    state.kick_deletions();
    state.send_email_later(
        email,
        mail::data_deleted(true),
        format!("deleted-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    label: String,
    scopes: Vec<Scope>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedToken {
    token: String,
}

fn valid_label(label: &str) -> ApiResult<String> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 64 || label.chars().any(char::is_control) {
        return Err(ApiErr::bad_request("Labels are 1 to 64 characters."));
    }
    Ok(label.to_owned())
}

async fn create_token(
    State(state): State<Shared>,
    auth: WebAuth,
    Json(request): Json<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    auth.require_active()?;
    auth.require_recent_auth()?;
    let label = valid_label(&request.label)?;
    if request.scopes.is_empty() {
        return Err(ApiErr::bad_request("Choose at least one scope."));
    }
    let email = auth.account.email.clone();
    let token = state
        .run(move |state| {
            let token = crate::routes::v1::issue_api_token(
                state,
                &auth.account,
                &label,
                &request.scopes,
                ClientKind::ManualToken,
            )?;
            state.registry().audit(
                &auth.token.token_id,
                "token-create",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(token)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "New API token",
            "A new API token was created for your account.",
        ),
        format!("token-{}", new_secret()),
    );
    Ok((StatusCode::CREATED, Json(CreatedToken { token })))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingInfo {
    user_code: String,
    device_label: String,
    requested_scopes: Vec<Scope>,
    expires_at_ms: i64,
}

fn pairing_not_found() -> ApiErr {
    ApiErr::not_found(
        "pairing_not_found",
        "No pending pairing with this code. Check the code shown in VRCX-0-Nanashi.",
    )
}

fn pending_pairing(state: &AppState, code: &str) -> ApiResult<crate::db::registry::PairingRow> {
    let code = token::normalize_user_code(code).map_err(|_| pairing_not_found())?;
    state
        .registry()
        .pairing_by_user_code(&code)?
        .filter(|p| p.status == "pending" && p.expires_at_ms > now_ms())
        .ok_or_else(pairing_not_found)
}

async fn pairing_info(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(code): Path<String>,
) -> ApiResult<Json<PairingInfo>> {
    auth.require_active()?;
    state.rate(rate::REAUTH, &format!("pair:{}", auth.account.account_id))?;
    state
        .run(move |state| {
            let pairing = pending_pairing(state, &code)?;
            Ok(Json(PairingInfo {
                user_code: pairing.user_code,
                device_label: pairing.device_label,
                requested_scopes: pairing.requested_scopes,
                expires_at_ms: pairing.expires_at_ms,
            }))
        })
        .await
}

#[derive(Deserialize)]
struct ApproveRequest {
    scopes: Vec<Scope>,
}

async fn pairing_approve(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(code): Path<String>,
    Json(request): Json<ApproveRequest>,
) -> ApiResult<StatusCode> {
    auth.require_active()?;
    auth.require_recent_auth()?;
    if request.scopes.is_empty() {
        return Err(ApiErr::bad_request("Choose at least one scope."));
    }
    let email = auth.account.email.clone();
    let label = state
        .run(move |state| {
            let pairing = pending_pairing(state, &code)?;
            let registry = state.registry();
            if !registry.decide_pairing(
                &pairing.user_code,
                &auth.account.account_id,
                Some(&request.scopes),
            )? {
                return Err(pairing_not_found());
            }
            registry.audit(
                &auth.token.token_id,
                "pair-approve",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(pairing.device_label)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "New device paired",
            &format!("A device was paired with your account: {label}."),
        ),
        format!("pair-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn pairing_deny(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(code): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_active()?;
    state
        .run(move |state| {
            let pairing = pending_pairing(state, &code)?;
            state
                .registry()
                .decide_pairing(&pairing.user_code, &auth.account.account_id, None)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

const MAX_ENVELOPES: i64 = 20;
const MAX_ENVELOPE_BYTES: usize = 4096;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeInfo {
    envelope_id: String,
    kind: &'static str,
    label: String,
    created_at_ms: i64,
}

fn envelope_kind(
    envelope: &vrcx_0_nanashi_website_protocol::envelope::KeyEnvelope,
) -> &'static str {
    match envelope.lock {
        vrcx_0_nanashi_website_protocol::envelope::EnvelopeLock::Passphrase { .. } => "passphrase",
        vrcx_0_nanashi_website_protocol::envelope::EnvelopeLock::PasskeyPrf { .. } => "passkey-prf",
    }
}

fn validate_envelope(
    body: &str,
) -> ApiResult<vrcx_0_nanashi_website_protocol::envelope::KeyEnvelope> {
    use vrcx_0_nanashi_website_protocol::envelope::{Argon2Cost, EnvelopeLock, KeyEnvelope};
    if body.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiErr::bad_request("Envelope too large."));
    }
    let envelope: KeyEnvelope =
        serde_json::from_str(body).map_err(|_| ApiErr::bad_request("Malformed envelope."))?;
    let id_ok = b64::decode(&envelope.envelope_id).is_ok_and(|bytes| bytes.len() == 16);
    if !id_ok
        || envelope.label.chars().count() > 64
        || envelope.nonce.len() != 24
        || envelope.ciphertext.len() != 48
    {
        return Err(ApiErr::bad_request("Malformed envelope."));
    }
    if let EnvelopeLock::Passphrase { cost, salt, .. } = &envelope.lock {
        let min = Argon2Cost::MINIMUM;
        if cost.m_kib < min.m_kib || cost.t < min.t || cost.p < min.p || salt.len() != 16 {
            return Err(ApiErr::bad_request(
                "Envelope parameters are below the minimum.",
            ));
        }
    }
    Ok(envelope)
}

async fn list_envelopes(
    State(state): State<Shared>,
    auth: WebAuth,
) -> ApiResult<Json<Vec<EnvelopeInfo>>> {
    auth.require_active()?;
    auth.require_recent_auth()?;
    state
        .run(move |state| {
            let store = state.open_store(&auth.account)?;
            let mut out = Vec::new();
            for (id, body, created) in store.envelopes()? {
                if let Ok(envelope) = validate_envelope(&body) {
                    out.push(EnvelopeInfo {
                        envelope_id: id,
                        kind: envelope_kind(&envelope),
                        label: envelope.label,
                        created_at_ms: created,
                    });
                }
            }
            Ok(Json(out))
        })
        .await
}

async fn create_envelope(
    State(state): State<Shared>,
    auth: WebAuth,
    body: String,
) -> ApiResult<StatusCode> {
    auth.require_active()?;
    auth.require_recent_auth()?;
    auth.require_sync_enabled()?;
    let envelope = validate_envelope(&body)?;
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            let mut store = state.open_store(&auth.account)?;
            store.put_envelope(
                &envelope.envelope_id,
                &body,
                now_ms(),
                AppState::limits(&auth.account),
                MAX_ENVELOPES,
            )?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            state.registry().audit(
                &auth.token.token_id,
                "envelope-create",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(())
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Key stored on the server",
            "An encrypted copy of your sync key (a key envelope) was stored on the server.",
        ),
        format!("envelope-{}", new_secret()),
    );
    Ok(StatusCode::CREATED)
}

async fn get_envelope(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(envelope_id): Path<String>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    auth.require_active()?;
    auth.require_recent_auth()?;
    state.rate(rate::ENVELOPE_FETCH, auth.account.account_id.as_str())?;
    let email = auth.account.email.clone();
    let body = state
        .run(move |state| {
            let store = state.open_store(&auth.account)?;
            let body = store.envelope(&envelope_id)?.ok_or_else(|| {
                ApiErr::not_found("envelope_not_found", "Key envelope not found.")
            })?;
            state.registry().audit(
                &auth.token.token_id,
                "envelope-fetch",
                Some(&auth.account.account_id),
                now_ms(),
            )?;
            Ok(body)
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Stored key downloaded",
            "The encrypted copy of your sync key was downloaded to unlock it in a browser.",
        ),
        format!("envelope-get-{}", new_secret()),
    );
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

async fn delete_envelope(
    State(state): State<Shared>,
    auth: WebAuth,
    Path(envelope_id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            let mut store = state.open_store(&auth.account)?;
            if !store.delete_envelope(&envelope_id)? {
                return Err(ApiErr::not_found(
                    "envelope_not_found",
                    "Key envelope not found.",
                ));
            }
            state.refresh_usage(&auth.account.account_id, &store)?;
            Ok(())
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Stored key deleted",
            "A stored copy of your sync key was deleted from the server.",
        ),
        format!("envelope-del-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_all_envelopes(State(state): State<Shared>, auth: WebAuth) -> ApiResult<StatusCode> {
    auth.require_recent_auth()?;
    let email = auth.account.email.clone();
    state
        .run(move |state| {
            if auth.account.wrapped_adk.is_none() {
                return Ok(());
            }
            let mut store = state.open_store(&auth.account)?;
            store.delete_all_envelopes()?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            Ok(())
        })
        .await?;
    state.send_email_later(
        email,
        mail::notice(
            "Stored keys deleted",
            "All stored copies of your sync key were deleted from the server.",
        ),
        format!("envelope-all-{}", new_secret()),
    );
    Ok(StatusCode::NO_CONTENT)
}

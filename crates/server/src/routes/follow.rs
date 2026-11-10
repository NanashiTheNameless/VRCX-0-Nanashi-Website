//! Anonymous follow link shares: no account, only a write token handed out
//! once, a proof-of-work check to create, and expiry after a day without
//! updates. The server only ever holds sealed locations it cannot read.

use altcha::{
    CreateChallengeOptions, Payload, VerifySolutionOptions, create_challenge, verify_solution,
};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL_NOPAD};
use vrcx_0_nanashi_website_protocol::api::{
    FollowShareCreate, FollowShareCreated, FollowShareOpen, FollowShareSealed, FollowShareUpdate,
    FollowShareView, codes,
};
use vrcx_0_nanashi_website_protocol::follow::{AUTH_LEN, MAX_SEALED_LEN};
use vrcx_0_nanashi_website_protocol::{b64, rand, token};

use crate::auth::ClientOrigin;
use crate::crypto::constant_time_eq;
use crate::http::{ApiErr, ApiResult};
use crate::rate::{self, Rule};
use crate::state::{AppState, Shared};
use crate::util::now_epoch;

/// A share disappears a day after its last update.
pub const FOLLOW_SHARE_TTL_SECS: i64 = 24 * 60 * 60;
const CODE_LEN: usize = 10;
const ALTCHA_PURPOSE: &str = "follow";

const CREATE_IP: Rule = Rule {
    name: "follow-create-ip",
    capacity: 5.0,
    per_second: 1.0 / 600.0,
};
const UPDATE_CODE: Rule = Rule::per_minute("follow-update-code", 6);
const VIEW_IP: Rule = Rule::per_minute("follow-view-ip", 60);
const OPEN_FAILURE_IP: Rule = Rule {
    name: "follow-open-fail-ip",
    capacity: 10.0,
    per_second: 1.0 / 60.0,
};
const OPEN_FAILURE_CODE: Rule = Rule {
    name: "follow-open-fail-code",
    capacity: 30.0,
    per_second: 1.0 / 120.0,
};
const WRITE_FAILURE_IP: Rule = Rule {
    name: "follow-write-fail-ip",
    capacity: 10.0,
    per_second: 1.0 / 60.0,
};

pub fn public_router() -> Router<Shared> {
    Router::new()
        .route("/follow/challenge", get(challenge))
        .route("/follow", post(create))
        .route("/follow/{code}", get(view).put(update).delete(remove))
        .route("/follow/{code}/open", post(open))
}

fn not_found() -> ApiErr {
    ApiErr::not_found(codes::FOLLOW_NOT_FOUND, "This follow link is not active.")
}

fn normalize_code(code: &str) -> ApiResult<String> {
    if code.len() != CODE_LEN || !code.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(not_found());
    }
    Ok(code.to_ascii_uppercase())
}

fn altcha_secret(state: &AppState) -> String {
    data_encoding::HEXLOWER.encode(&state.keys.hmac("altcha-follow-v1", b"follow-share"))
}

fn write_hash(state: &AppState, code: &str, token: &str) -> [u8; 32] {
    state
        .keys
        .hmac("follow-write-v1", format!("{code}:{token}").as_bytes())
}

fn auth_hash(state: &AppState, code: &str, auth: &[u8]) -> [u8; 32] {
    let mut data = code.as_bytes().to_vec();
    data.push(b':');
    data.extend_from_slice(auth);
    state.keys.hmac("follow-auth-v1", &data)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= 128)
}

async fn challenge(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<Json<altcha::Challenge>> {
    state.rate(
        rate::ALTCHA_CHALLENGE_IP,
        &ClientOrigin::from_headers(&headers).rate_key(),
    )?;
    state
        .run(move |state| {
            let challenge = create_challenge(CreateChallengeOptions {
                algorithm: "PBKDF2/SHA-256".to_owned(),
                cost: if cfg!(test) { 1 } else { 5_000 },
                data: Some(std::collections::BTreeMap::from([(
                    "purpose".to_owned(),
                    serde_json::Value::String(ALTCHA_PURPOSE.to_owned()),
                )])),
                expires_at: Some(now_epoch() + 300),
                hmac_signature_secret: Some(altcha_secret(state)),
                ..Default::default()
            })
            .map_err(|error| ApiErr::internal("altcha challenge", error))?;
            Ok(Json(challenge))
        })
        .await
}

fn verify_altcha(state: &AppState, encoded: &str) -> ApiResult<String> {
    let rejected = || ApiErr::bad_request("Complete the bot check and try again.");
    if encoded.len() > 16 * 1024 {
        return Err(rejected());
    }
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(encoded.as_bytes()))
        .map_err(|_| rejected())?;
    let payload: Payload = serde_json::from_slice(&decoded).map_err(|_| rejected())?;
    if payload
        .challenge
        .parameters
        .data
        .as_ref()
        .and_then(|data| data.get("purpose"))
        .and_then(serde_json::Value::as_str)
        != Some(ALTCHA_PURPOSE)
    {
        return Err(rejected());
    }
    let signature = payload.challenge.signature.clone().ok_or_else(rejected)?;
    let verified = verify_solution(VerifySolutionOptions::new(
        &payload.challenge,
        &payload.solution,
        altcha_secret(state),
    ))
    .map_err(|_| rejected())?;
    if !verified.verified {
        return Err(rejected());
    }
    Ok(signature)
}

async fn create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(request): Json<FollowShareCreate>,
) -> ApiResult<(StatusCode, Json<FollowShareCreated>)> {
    let origin = ClientOrigin::from_headers(&headers).rate_key();
    state.rate(CREATE_IP, &origin)?;
    let signature = verify_altcha(&state, &request.altcha)?;
    state.rate(rate::ALTCHA_USED, &format!("follow:{signature}"))?;
    if let Some(password) = &request.password {
        password
            .lock
            .check()
            .map_err(|_| ApiErr::bad_request("The password settings are not accepted."))?;
        if password.auth.len() != AUTH_LEN {
            return Err(ApiErr::bad_request(
                "The password settings are not accepted.",
            ));
        }
    }
    state
        .run(move |state| {
            let now = now_epoch();
            let expires_at = now + FOLLOW_SHARE_TTL_SECS;
            let write_token = BASE64URL_NOPAD
                .encode(&rand::bytes::<32>().map_err(|error| ApiErr::internal("rng", error))?);
            let lock_json = request
                .password
                .as_ref()
                .map(|password| serde_json::to_string(&password.lock))
                .transpose()
                .map_err(|error| ApiErr::internal("follow lock", error))?;
            for _ in 0..8 {
                let code: String = token::generate_user_code()
                    .map_err(|error| ApiErr::internal("rng", error))?
                    .replace('-', "")
                    .chars()
                    .chain(
                        token::generate_user_code()
                            .map_err(|error| ApiErr::internal("rng", error))?
                            .replace('-', "")
                            .chars(),
                    )
                    .take(CODE_LEN)
                    .collect();
                let auth = request
                    .password
                    .as_ref()
                    .map(|password| auth_hash(state, &code, &password.auth));
                if state.registry().create_follow_share(
                    &code,
                    &write_hash(state, &code, &write_token),
                    auth.as_ref().map(|hash| hash.as_slice()),
                    lock_json.as_deref(),
                    now,
                    expires_at,
                )? {
                    return Ok((
                        StatusCode::CREATED,
                        Json(FollowShareCreated {
                            code,
                            write_token,
                            expires_at,
                        }),
                    ));
                }
            }
            Err(ApiErr::internal("rng", "could not allocate a follow code"))
        })
        .await
}

fn check_writer(
    state: &AppState,
    headers: &HeaderMap,
    code: &str,
    expected: &[u8],
) -> ApiResult<()> {
    let origin = ClientOrigin::from_headers(headers).rate_key();
    let valid = bearer(headers)
        .is_some_and(|token| constant_time_eq(&write_hash(state, code, token), expected));
    if !valid {
        state.rate(WRITE_FAILURE_IP, &origin)?;
        return Err(ApiErr::unauthorized());
    }
    Ok(())
}

async fn update(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(request): Json<FollowShareUpdate>,
) -> ApiResult<StatusCode> {
    let code = normalize_code(&code)?;
    if request.sealed.is_empty() || request.sealed.len() > MAX_SEALED_LEN {
        return Err(ApiErr::bad_request("The location data is not accepted."));
    }
    state
        .run(move |state| {
            let now = now_epoch();
            let row = state
                .registry()
                .follow_share(&code, now)?
                .ok_or_else(not_found)?;
            check_writer(state, &headers, &code, &row.write_hash)?;
            state.rate(UPDATE_CODE, &code)?;
            if !state.registry().update_follow_share(
                &code,
                &request.sealed,
                now,
                now + FOLLOW_SHARE_TTL_SECS,
            )? {
                return Err(not_found());
            }
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn remove(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> ApiResult<StatusCode> {
    let code = normalize_code(&code)?;
    state
        .run(move |state| {
            let row = state
                .registry()
                .follow_share(&code, now_epoch())?
                .ok_or_else(not_found)?;
            check_writer(state, &headers, &code, &row.write_hash)?;
            state.registry().delete_follow_share(&code)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn view(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> ApiResult<Json<FollowShareView>> {
    state.rate(VIEW_IP, &ClientOrigin::from_headers(&headers).rate_key())?;
    let code = normalize_code(&code)?;
    state
        .run(move |state| {
            let row = state
                .registry()
                .follow_share(&code, now_epoch())?
                .ok_or_else(not_found)?;
            let password = row
                .lock_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| ApiErr::internal("follow lock", error))?;
            let sealed = if row.auth_hash.is_some() {
                None
            } else {
                row.sealed.as_deref().map(b64::encode)
            };
            Ok(Json(FollowShareView {
                updated_at: row.updated_at,
                expires_at: row.expires_at,
                password,
                sealed,
            }))
        })
        .await
}

async fn open(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(request): Json<FollowShareOpen>,
) -> ApiResult<Json<FollowShareSealed>> {
    let code = normalize_code(&code)?;
    let origin = ClientOrigin::from_headers(&headers).rate_key();
    state.rate(VIEW_IP, &origin)?;
    state
        .run(move |state| {
            let row = state
                .registry()
                .follow_share(&code, now_epoch())?
                .ok_or_else(not_found)?;
            let Some(expected) = row.auth_hash else {
                return Err(ApiErr::bad_request("This follow link has no password."));
            };
            if request.auth.len() != AUTH_LEN
                || !constant_time_eq(&auth_hash(state, &code, &request.auth), &expected)
            {
                state.rate(OPEN_FAILURE_IP, &origin)?;
                state.rate(OPEN_FAILURE_CODE, &code)?;
                return Err(ApiErr::new(
                    StatusCode::FORBIDDEN,
                    codes::ACCESS_DENIED,
                    "Wrong password.",
                ));
            }
            let sealed = row.sealed.ok_or_else(|| {
                ApiErr::not_found(codes::FOLLOW_NOT_FOUND, "No location has been shared yet.")
            })?;
            Ok(Json(FollowShareSealed {
                updated_at: row.updated_at,
                sealed,
            }))
        })
        .await
}

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::Deserialize;
use vrcx_0_nanashi_website_protocol::api::{
    self, AccountInfo, Capabilities, ChunkList, ChunkListItem, ChunkStored, ClientInfo,
    ClientIpEntry, ClientLocation, CollectorCapabilities, CompactRequest, CreateVaultRequest,
    DeviceAuthorizeRequest, DeviceAuthorizeResponse, DeviceTokenRequest, DeviceTokenResponse,
    Limits, ReauthMethod, ReauthRequest, Scope, TransferCreateRequest, TransferCreated,
    TransferKey, VaultInfo, codes, headers,
};
use vrcx_0_nanashi_website_protocol::b64;
use vrcx_0_nanashi_website_protocol::ids::{AccountId, ChunkId, VaultId};
use vrcx_0_nanashi_website_protocol::seal::SealPublicKey;
use vrcx_0_nanashi_website_protocol::token::{self, TokenKind};
use vrcx_0_nanashi_website_protocol::transfer;

use crate::auth::{ApiAuth, ClientOrigin, TOKEN_HMAC_PURPOSE};
use crate::db::account::{AccountStore, ChunkCheck, ChunkPage, NewChunk, ObjectId};
use crate::db::registry::{AccountRow, AccountState, NewToken, TokenRow};
use crate::http::{ApiErr, ApiResult};
use crate::rate;
use crate::state::AccountKeys;
use crate::state::{AppState, Shared};
use crate::totp;
use crate::util::{DAY_MS, now_ms};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

pub const ACTIVE_WINDOW_MS: i64 = 5 * 60 * 1000;
pub const RECENT_AUTH_MS: i64 = 10 * 60 * 1000;
pub const PAIRING_TTL_MS: i64 = 10 * 60 * 1000;
pub const TRANSFER_TTL_MS: i64 = 10 * 60 * 1000;
pub const PAIRING_INTERVAL_S: i64 = 5;
pub const BATCH_BYTE_CAP: u64 = 16 * 1024 * 1024;
pub const PARALLEL_FETCHES: usize = 16;
pub const MAX_TOKENS: i64 = 20;
const DEVICE_CODE_PURPOSE: &str = "device-code";

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/capabilities", get(capabilities))
        .route("/instance", get(instance))
        .route("/device/authorize", post(device_authorize))
        .route("/device/token", post(device_token))
        .route("/account/tokens", get(list_tokens))
        .route("/account/tokens/current", delete(revoke_current))
        .route("/account/reauth", post(reauth))
        .merge(shared_routes())
}

pub fn shared_routes() -> Router<Shared> {
    Router::new()
        .route("/account", get(account_info))
        .route("/account/clients", get(list_clients))
        .route("/account/clients/revoke-others", post(revoke_others))
        .route("/account/clients/history", delete(clear_history))
        .route("/account/clients/{client_id}/revoke", post(revoke_client))
        .route("/account/data", delete(delete_data))
        .route("/vaults", get(list_vaults).post(create_vault))
        .route("/vaults/{vault_id}", delete(delete_vault))
        .route(
            "/vaults/{vault_id}/manifest",
            get(get_manifest).put(put_manifest),
        )
        .route(
            "/vaults/{vault_id}/chunks",
            get(list_chunks).post(post_chunk),
        )
        .route("/vaults/{vault_id}/chunks:batch", get(batch_chunks))
        .route("/vaults/{vault_id}/chunks/{seq}", get(get_chunk))
        .route("/vaults/{vault_id}/compact", post(compact))
        .route("/vaults/{vault_id}/live", get(get_live))
        .route("/vaults/{vault_id}/collector", get(collector_status))
        .route(
            "/vaults/{vault_id}/collector/unlock",
            post(collector_unlock),
        )
        .route("/vaults/{vault_id}/collector/lock", post(collector_lock))
        .route("/transfer", post(transfer_create))
        .route(
            "/transfer/{transfer_id}",
            get(transfer_key).put(transfer_complete),
        )
        .route("/transfer/{transfer_id}/result", get(transfer_result))
        .route(
            "/collections",
            get(crate::routes::collections::list_owned).post(crate::routes::collections::create),
        )
        .route(
            "/collections/{code}",
            get(crate::routes::collections::get_owned)
                .put(crate::routes::collections::update)
                .delete(crate::routes::collections::delete),
        )
}

fn parse_vault(value: &str) -> ApiResult<VaultId> {
    value
        .parse()
        .map_err(|_| ApiErr::not_found(codes::VAULT_NOT_FOUND, "Vault not found."))
}

async fn instance(State(state): State<Shared>) -> ApiResult<Json<serde_json::Value>> {
    match (
        state
            .config
            .instance_statement
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
        state
            .config
            .instance_signature
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) {
        (Some(statement), Some(signature)) => Ok(Json(serde_json::json!({
            "statement": statement,
            "signature": signature,
        }))),
        _ => Err(ApiErr::new(
            StatusCode::NOT_FOUND,
            "instance_not_attested",
            "This server has no instance statement.",
        )),
    }
}

async fn capabilities(
    State(state): State<Shared>,
    request_headers: HeaderMap,
) -> ApiResult<Json<Capabilities>> {
    state.rate(
        rate::CAPABILITIES,
        &ClientOrigin::from_headers(&request_headers).rate_key(),
    )?;
    Ok(Json(Capabilities {
        server: api::SERVER_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        commit: state.config.commit.clone(),
        protocol: vec![api::PROTOCOL_VERSION],
        web_api: vec![1],
        registration: crate::routes::web::effective_registration(&state),
        website_origins: state.config.web_origins.clone(),
        collector: collector_capabilities(&state).await,
        limits: Limits {
            max_chunk_bytes: api::MAX_CHUNK_BYTES as u64,
            max_request_bytes: api::MAX_REQUEST_BYTES as u64,
        },
        policy_url: state.config.policy_url.clone(),
    }))
}

fn valid_scopes(scopes: &[Scope]) -> bool {
    !scopes.is_empty() && scopes.len() <= 4
}

async fn device_authorize(
    State(state): State<Shared>,
    request_headers: HeaderMap,
    Json(request): Json<DeviceAuthorizeRequest>,
) -> ApiResult<Json<DeviceAuthorizeResponse>> {
    state.rate(
        rate::DEVICE_AUTHORIZE,
        &ClientOrigin::from_headers(&request_headers).rate_key(),
    )?;
    let label = request.device_label.trim().to_owned();
    if label.is_empty() || label.chars().count() > 64 || !valid_scopes(&request.requested_scopes) {
        return Err(ApiErr::bad_request(
            "deviceLabel must be 1-64 characters and requestedScopes non-empty.",
        ));
    }
    state
        .run(move |state| {
            let device_code =
                token::generate_device_code().map_err(|e| ApiErr::internal("rng", e))?;
            let hash = state.keys.hmac(DEVICE_CODE_PURPOSE, device_code.as_bytes());
            let registry = state.registry();
            registry.prune_expired(now_ms())?;
            for _ in 0..8 {
                let user_code =
                    token::generate_user_code().map_err(|e| ApiErr::internal("rng", e))?;
                if registry.pairing_by_user_code(&user_code)?.is_some() {
                    continue;
                }
                registry.insert_pairing(
                    &hash,
                    &user_code,
                    &label,
                    &request.requested_scopes,
                    now_ms() + PAIRING_TTL_MS,
                )?;
                let website = state
                    .config
                    .web_origins
                    .first()
                    .cloned()
                    .unwrap_or_default();
                return Ok(Json(DeviceAuthorizeResponse {
                    device_code: device_code.to_string(),
                    user_code,
                    verification_uri: format!("{website}/pair"),
                    expires_in: (PAIRING_TTL_MS / 1000) as u32,
                    interval: PAIRING_INTERVAL_S as u32,
                }));
            }
            Err(ApiErr::internal(
                "pairing",
                "could not allocate a user code",
            ))
        })
        .await
}

pub fn issue_api_token(
    state: &AppState,
    account: &AccountRow,
    label: &str,
    scopes: &[Scope],
    client_kind: api::ClientKind,
) -> ApiResult<String> {
    let registry = state.registry();
    if !account.is_owner() && registry.count_live_tokens(&account.account_id)? >= MAX_TOKENS {
        return Err(ApiErr::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            codes::QUOTA_EXCEEDED,
            "This account has reached its token limit. Revoke an old client first.",
        ));
    }
    let (full, parts) = token::generate(TokenKind::Api).map_err(|e| ApiErr::internal("rng", e))?;
    registry.insert_token(&NewToken {
        token_id: &parts.id,
        account_id: &account.account_id,
        kind: "api",
        client_kind,
        secret_hmac: &state.keys.hmac(TOKEN_HMAC_PURPOSE, &parts.secret),
        scopes,
        label,
        client_version: None,
        now_ms: now_ms(),
        expires_at_ms: None,
        idle_timeout_ms: None,
    })?;
    Ok(full.to_string())
}

async fn device_token(
    State(state): State<Shared>,
    request_headers: HeaderMap,
    Json(request): Json<DeviceTokenRequest>,
) -> ApiResult<Json<DeviceTokenResponse>> {
    state.rate(
        rate::DEVICE_TOKEN,
        &ClientOrigin::from_headers(&request_headers).rate_key(),
    )?;
    state
        .run(move |state| {
            let hash = state
                .keys
                .hmac(DEVICE_CODE_PURPOSE, request.device_code.as_bytes());
            let now = now_ms();
            let pairing = {
                let registry = state.registry();
                let pairing = registry.pairing_by_device_code(&hash)?;
                match pairing {
                    Some(p) if p.expires_at_ms > now => {
                        if now < p.next_poll_ms {
                            let interval = p.interval_s + 5;
                            registry.set_pairing_poll(&hash, now + interval * 1000, interval)?;
                            return Err(ApiErr::pending(codes::SLOW_DOWN, "Polling too fast."));
                        }
                        registry.set_pairing_poll(
                            &hash,
                            now + p.interval_s * 1000,
                            p.interval_s,
                        )?;
                        p
                    }
                    _ => {
                        return Err(ApiErr::pending(
                            codes::EXPIRED_TOKEN,
                            "Pairing expired. Start again.",
                        ));
                    }
                }
            };
            match pairing.status.as_str() {
                "pending" => Err(ApiErr::pending(
                    codes::AUTHORIZATION_PENDING,
                    "Waiting for approval on the website.",
                )),
                "denied" => {
                    state.registry().delete_pairing(&hash)?;
                    Err(ApiErr::pending(codes::ACCESS_DENIED, "Pairing was denied."))
                }
                _ => {
                    let account_id = pairing
                        .account_id
                        .ok_or_else(|| ApiErr::internal("pairing", "no account"))?;
                    let scopes = pairing.approved_scopes.unwrap_or_default();
                    let account = state.registry().account(&account_id)?.ok_or_else(|| {
                        ApiErr::pending(codes::ACCESS_DENIED, "Account no longer exists.")
                    })?;
                    let token = issue_api_token(
                        state,
                        &account,
                        &pairing.device_label,
                        &scopes,
                        api::ClientKind::Desktop,
                    )?;
                    state.registry().delete_pairing(&hash)?;
                    Ok(Json(DeviceTokenResponse {
                        account_id,
                        token,
                        scopes,
                    }))
                }
            }
        })
        .await
}

async fn account_info(auth: ApiAuth) -> Json<AccountInfo> {
    Json(AccountInfo {
        account_id: auth.account.account_id.clone(),
        usage_bytes: auth.account.usage_bytes,
        quota_bytes: auth.account.effective_quota(),
        collector_allowed: auth.account.effective_collector_allowed(),
        sync_allowed: auth.account.sync_allowed,
        scopes: auth.token.scopes.clone(),
    })
}

fn location(
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
) -> ClientLocation {
    ClientLocation {
        city,
        region,
        country,
    }
}

fn client_infos(
    state: &AppState,
    auth: &ApiAuth,
    with_history: bool,
) -> ApiResult<Vec<ClientInfo>> {
    let registry = state.registry();
    let tokens = registry.tokens_for(&auth.account.account_id)?;
    let ips = registry.client_ips(&auth.account.account_id)?;
    let cutoff = auth.now_ms - 90 * DAY_MS;
    Ok(tokens
        .into_iter()
        .map(|token: TokenRow| {
            let history: Vec<ClientIpEntry> = ips
                .iter()
                .filter(|ip| ip.client_id == token.token_id && ip.last_seen_ms >= cutoff)
                .map(|ip| ClientIpEntry {
                    ip: ip.ip.clone(),
                    location: location(ip.city.clone(), ip.region.clone(), ip.country.clone()),
                    first_seen_ms: ip.first_seen_ms,
                    last_seen_ms: ip.last_seen_ms,
                })
                .collect();
            let first_seen = history.iter().map(|h| h.first_seen_ms).min();
            ClientInfo {
                current: token.token_id == auth.token.token_id,
                active_now: token.revoked_at_ms.is_none()
                    && token.last_used_ms.is_some_and(|last| {
                        auth.now_ms - last
                            < ACTIVE_WINDOW_MS + crate::state::CLIENT_WRITE_INTERVAL_MS
                    }),
                client_id: token.token_id,
                kind: token.client_kind,
                label: token.label,
                client_version: token.client_version,
                scopes: token.scopes,
                revoked_at_ms: token.revoked_at_ms,
                first_seen_ms: first_seen,
                last_seen_ms: token.last_used_ms,
                current_ip: history.first().cloned(),
                history: if with_history { history } else { Vec::new() },
            }
        })
        .collect())
}

async fn list_tokens(
    State(state): State<Shared>,
    auth: ApiAuth,
) -> ApiResult<Json<Vec<ClientInfo>>> {
    state
        .run(move |state| Ok(Json(client_infos(state, &auth, false)?)))
        .await
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    history: bool,
}

async fn list_clients(
    State(state): State<Shared>,
    auth: ApiAuth,
    Query(query): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<ClientInfo>>> {
    auth.require(Scope::Account)?;
    state
        .run(move |state| Ok(Json(client_infos(state, &auth, query.history)?)))
        .await
}

async fn revoke_current(State(state): State<Shared>, auth: ApiAuth) -> ApiResult<StatusCode> {
    state
        .run(move |state| {
            let registry = state.registry();
            registry.revoke_token(
                &auth.account.account_id,
                &auth.token.token_id,
                &auth.token.token_id,
                auth.now_ms,
            )?;
            registry.audit(
                &auth.token.token_id,
                "revoke-self",
                Some(&auth.account.account_id),
                auth.now_ms,
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

pub fn check_second_factor(
    state: &AppState,
    account: &AccountRow,
    method: ReauthMethod,
    code: &str,
    now: i64,
) -> ApiResult<bool> {
    let registry = state.registry();
    match method {
        ReauthMethod::Totp => {
            let Some((Some(kind), Some(wrapped), last_step)) =
                registry.twofa(&account.account_id)?
            else {
                return Ok(false);
            };
            if kind != "totp" {
                return Ok(false);
            }
            let secret = state
                .keys
                .unwrap(&format!("totp:{}", account.account_id), &wrapped)
                .map_err(|e| ApiErr::internal("totp secret", e))?;
            match totp::verify(&secret, code, now, last_step) {
                Some(step) => Ok(registry.advance_totp_step(&account.account_id, step)?),
                None => Ok(false),
            }
        }
        ReauthMethod::Recovery => {
            let Some(code) = crate::recovery::normalize(code) else {
                return Ok(false);
            };
            let hash = crate::recovery::hash(&state.keys, &code);
            Ok(registry.use_recovery_code(&account.account_id, &hash, now)?)
        }
        ReauthMethod::Email => Ok(false),
    }
}

async fn reauth(
    State(state): State<Shared>,
    auth: ApiAuth,
    Json(request): Json<ReauthRequest>,
) -> ApiResult<StatusCode> {
    state.rate(rate::REAUTH, auth.account.account_id.as_str())?;
    if request.method == ReauthMethod::Email {
        let Some(code) = request.code.filter(|code| !code.trim().is_empty()) else {
            crate::routes::web::send_email_code(&state, &auth.account, "reauth").await?;
            return Ok(StatusCode::ACCEPTED);
        };
        let shared = state.clone();
        return state
            .run(move |state| {
                if !crate::routes::web::second_factor(
                    &shared,
                    &auth.account,
                    ReauthMethod::Email,
                    &code,
                    "reauth",
                )? {
                    return Err(ApiErr::new(
                        StatusCode::UNAUTHORIZED,
                        codes::UNAUTHORIZED,
                        "Code not accepted.",
                    ));
                }
                state
                    .registry()
                    .set_recent_auth(&auth.token.token_id, auth.now_ms + RECENT_AUTH_MS)?;
                Ok(StatusCode::NO_CONTENT)
            })
            .await;
    }
    let code = request
        .code
        .ok_or_else(|| ApiErr::bad_request("code is required."))?;
    state
        .run(move |state| {
            if !check_second_factor(state, &auth.account, request.method, &code, auth.now_ms)? {
                return Err(ApiErr::new(
                    StatusCode::UNAUTHORIZED,
                    codes::UNAUTHORIZED,
                    "Code not accepted.",
                ));
            }
            state
                .registry()
                .set_recent_auth(&auth.token.token_id, auth.now_ms + RECENT_AUTH_MS)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn revoke_client(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(client_id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require(Scope::Account)?;
    auth.require_recent_auth()?;
    state
        .run(move |state| {
            let registry = state.registry();
            if !registry.revoke_token(
                &auth.account.account_id,
                &client_id,
                &auth.token.token_id,
                auth.now_ms,
            )? {
                return Err(ApiErr::not_found(
                    codes::CLIENT_NOT_FOUND,
                    "Client not found or already revoked.",
                ));
            }
            registry.audit(
                &auth.token.token_id,
                "revoke-client",
                Some(&auth.account.account_id),
                auth.now_ms,
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn revoke_others(State(state): State<Shared>, auth: ApiAuth) -> ApiResult<StatusCode> {
    auth.require(Scope::Account)?;
    auth.require_recent_auth()?;
    state
        .run(move |state| {
            let registry = state.registry();
            registry.revoke_all_except(
                &auth.account.account_id,
                &auth.token.token_id,
                &auth.token.token_id,
                auth.now_ms,
            )?;
            registry.audit(
                &auth.token.token_id,
                "revoke-others",
                Some(&auth.account.account_id),
                auth.now_ms,
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientQuery {
    client_id: Option<String>,
}

async fn clear_history(
    State(state): State<Shared>,
    auth: ApiAuth,
    Query(query): Query<ClientQuery>,
) -> ApiResult<StatusCode> {
    auth.require(Scope::Account)?;
    auth.require_recent_auth()?;
    state
        .run(move |state| {
            state
                .registry()
                .clear_client_ips(&auth.account.account_id, query.client_id.as_deref())?;
            state.forget_client_writes(query.client_id.as_deref());
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn delete_data(State(state): State<Shared>, auth: ApiAuth) -> ApiResult<StatusCode> {
    auth.require(Scope::Account)?;
    auth.require_recent_auth_on_web()?;
    let account_id = auth.account.account_id.to_string();
    state
        .run(move |state| {
            state.delete_account_data(&auth.account.account_id)?;
            state.registry().audit(
                &auth.token.token_id,
                "delete-data",
                Some(&auth.account.account_id),
                auth.now_ms,
            )?;
            Ok(())
        })
        .await?;
    lock_collector_account(&state, &account_id).await;
    state.clear_live_snapshot(&account_id, None);
    state.kick_deletions();
    Ok(StatusCode::NO_CONTENT)
}

async fn list_vaults(
    State(state): State<Shared>,
    auth: ApiAuth,
) -> ApiResult<Json<Vec<VaultInfo>>> {
    auth.require_sync(Scope::Sync)?;
    state
        .run(move |state| {
            let store = state.open_store(&auth.account)?;
            Ok(Json(
                store
                    .vaults()?
                    .into_iter()
                    .map(|vault| VaultInfo {
                        vault_id: vault.vault_id,
                        vault_pk: b64::encode(&vault.vault_pk),
                        manifest_pk: b64::encode(&vault.manifest_pk),
                        created_at_ms: vault.created_at_ms,
                        max_seq: vault.max_seq,
                        manifest_seq: vault.manifest_seq,
                        usage_bytes: vault.usage_bytes,
                    })
                    .collect(),
            ))
        })
        .await
}

async fn create_vault(
    State(state): State<Shared>,
    auth: ApiAuth,
    Json(request): Json<CreateVaultRequest>,
) -> ApiResult<StatusCode> {
    auth.require_sync(Scope::Account)?;
    let vault_pk = b64::decode(&request.vault_pk)
        .map_err(|_| ApiErr::bad_request("vaultPk is not base64url."))?;
    SealPublicKey::from_bytes(&vault_pk)
        .map_err(|_| ApiErr::bad_request("vaultPk is not an X25519 public key."))?;
    let manifest_pk = b64::decode(&request.manifest_pk)
        .map_err(|_| ApiErr::bad_request("manifestPk is not base64url."))?;
    vrcx_0_nanashi_website_protocol::keys::verifying_key(&manifest_pk)
        .map_err(|_| ApiErr::bad_request("manifestPk is not an Ed25519 public key."))?;
    state
        .run(move |state| {
            let mut store = state.open_store(&auth.account)?;
            store.create_vault(
                &request.vault_id,
                &vault_pk,
                &manifest_pk,
                auth.now_ms,
                AppState::limits(&auth.account),
            )?;
            Ok(StatusCode::CREATED)
        })
        .await
}

async fn delete_vault(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require_sync(Scope::Account)?;
    auth.require_recent_auth_on_web()?;
    let vault_id = parse_vault(&vault_id)?;
    let live_account_id = auth.account.account_id.clone();
    state
        .run(move |state| {
            let (mut store, keys) = state.open_store_with_keys(&auth.account)?;
            let objects = store.delete_vault(&vault_id)?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            state.enqueue_object_deletions(&keys, &objects)?;
            Ok(())
        })
        .await?;
    let _ = crate::uds::call(
        &state.config.collector_socket,
        Method::POST,
        &format!("/lock/{live_account_id}/{vault_id}"),
        Vec::new(),
        false,
    )
    .await;
    state.clear_live_snapshot(live_account_id.as_str(), Some(&vault_id.to_string()));
    state.kick_deletions();
    Ok(StatusCode::NO_CONTENT)
}

async fn get_manifest(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
) -> ApiResult<Response> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    state
        .run(move |state| {
            let store = state.open_store(&auth.account)?;
            let (seq, blob) = store.manifest(&vault_id)?.ok_or_else(|| {
                ApiErr::not_found(codes::MANIFEST_NOT_FOUND, "No manifest uploaded yet.")
            })?;
            Ok(binary(blob, &[(headers::MANIFEST_SEQ, seq.to_string())]))
        })
        .await
}

fn header_u64(headers: &HeaderMap, name: &str) -> ApiResult<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| ApiErr::bad_request(format!("{name} header is required.")))
}

async fn put_manifest(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    request_headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    let seq = header_u64(&request_headers, headers::MANIFEST_SEQ)?;
    let previous = header_u64(&request_headers, headers::IF_MATCH_SEQ)?;
    if previous + 1 != seq {
        return Err(ApiErr::bad_request(
            "If-Match-Seq must be X-Manifest-Seq minus one.",
        ));
    }
    if body.is_empty() || body.len() > 1024 * 1024 {
        return Err(ApiErr::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::TOO_LARGE,
            "Manifest must be 1 byte to 1 MiB.",
        ));
    }
    state
        .run(move |state| {
            let mut store = state.open_store(&auth.account)?;
            store.put_manifest(&vault_id, seq, &body, AppState::limits(&auth.account))?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

fn binary(body: Vec<u8>, extra: &[(&'static str, String)]) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    for (name, value) in extra {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(*name, value);
        }
    }
    response
}

enum Upload {
    Done(u64),
    Store {
        object_id: ObjectId,
        key: String,
        sealed: Vec<u8>,
    },
}

async fn post_chunk(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    request_headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<ChunkStored>)> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    let chunk_id: ChunkId = request_headers
        .get(headers::CHUNK_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| ApiErr::bad_request("X-Chunk-Id header is required."))?;
    if body.is_empty() || body.len() > api::MAX_CHUNK_BYTES {
        return Err(ApiErr::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::TOO_LARGE,
            "Chunk is empty or too large.",
        ));
    }
    let blob_hash: [u8; 32] = Sha256::digest(&body).into();
    let size = body.len() as u64;
    let account = auth.account.clone();
    let upload = state
        .run(move |state| {
            let (store, keys) = state.open_store_with_keys(&account)?;
            match store.check_chunk(
                &vault_id,
                &chunk_id,
                &blob_hash,
                size,
                AppState::limits(&account),
            )? {
                ChunkCheck::Existing(seq) => Ok(Upload::Done(seq)),
                ChunkCheck::New => {
                    let object_id: ObjectId = crate::util::random_bytes();
                    let key = keys.object_key(&object_id);
                    let sealed = keys.seal_object(&key, &body);
                    Ok(Upload::Store {
                        object_id,
                        key,
                        sealed,
                    })
                }
            }
        })
        .await?;
    let (object_id, key) = match upload {
        Upload::Done(seq) => return Ok((StatusCode::CREATED, Json(ChunkStored { seq }))),
        Upload::Store {
            object_id,
            key,
            sealed,
        } => {
            state
                .objects
                .put(&key, sealed)
                .await
                .map_err(ApiErr::storage)?;
            (object_id, key)
        }
    };
    let account = auth.account.clone();
    let result = state
        .run(move |state| {
            let (mut store, keys) = state.open_store_with_keys(&account)?;
            let inserted = store.insert_chunk(
                &vault_id,
                &NewChunk {
                    chunk_id: &chunk_id,
                    object_id,
                    blob_hash,
                    size,
                },
                AppState::limits(&account),
            );
            match inserted {
                Ok((seq, duplicate)) => {
                    if duplicate {
                        state.enqueue_object_deletions(&keys, &[object_id])?;
                    }
                    state.refresh_usage(&account.account_id, &store)?;
                    Ok(seq)
                }
                Err(error) => {
                    state.enqueue_object_deletions(&keys, &[object_id])?;
                    Err(error.into())
                }
            }
        })
        .await;
    if result.is_err() {
        tracing::debug!(%key, "chunk insert failed after upload; object queued for deletion");
        state.kick_deletions();
    }
    let seq = result?;
    Ok((StatusCode::CREATED, Json(ChunkStored { seq })))
}

async fn fetch_chunk(
    state: &Shared,
    keys: &AccountKeys,
    object_id: &ObjectId,
) -> ApiResult<Vec<u8>> {
    let key = keys.object_key(object_id);
    let sealed = state
        .objects
        .get(&key)
        .await
        .map_err(ApiErr::storage)?
        .ok_or_else(|| ApiErr::internal("object storage", format!("object missing: {key}")))?;
    keys.open_object(&key, &sealed)
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default)]
    after: u64,
    before: Option<u64>,
    limit: Option<u32>,
}

impl PageQuery {
    fn limit(&self) -> u32 {
        self.limit.unwrap_or(200).clamp(1, 500)
    }

    fn page(&self, store: &AccountStore, vault_id: &VaultId) -> ApiResult<ChunkPage> {
        match self.before {
            Some(before) if self.after == 0 => store
                .chunk_page_before(vault_id, before, self.limit(), BATCH_BYTE_CAP)
                .map_err(ApiErr::from),
            Some(_) => Err(ApiErr::bad_request("Use either before or after, not both.")),
            None => store
                .chunk_page(vault_id, self.after, self.limit(), BATCH_BYTE_CAP)
                .map_err(ApiErr::from),
        }
    }
}

async fn list_chunks(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<ChunkList>> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    state
        .run(move |state| {
            let store = state.open_store(&auth.account)?;
            let page = query.page(&store, &vault_id)?;
            Ok(Json(ChunkList {
                chunks: page
                    .chunks
                    .into_iter()
                    .map(|meta| ChunkListItem {
                        seq: meta.seq,
                        chunk_id: meta.chunk_id,
                        size: meta.size,
                    })
                    .collect(),
                max_seq: page.max_seq,
                has_more: page.has_more,
            }))
        })
        .await
}

async fn batch_chunks(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    let (page, keys) = state
        .run(move |state| {
            let (store, keys) = state.open_store_with_keys(&auth.account)?;
            let page = query.page(&store, &vault_id)?;
            Ok((page, keys))
        })
        .await?;
    let keys = std::sync::Arc::new(keys);
    let object_ids: Vec<ObjectId> = page.chunks.iter().map(|meta| meta.object_id).collect();
    let blobs: Vec<ApiResult<Vec<u8>>> =
        futures_util::stream::iter(object_ids.into_iter().map(|object_id| {
            let state = state.clone();
            let keys = keys.clone();
            async move { fetch_chunk(&state, &keys, &object_id).await }
        }))
        .buffered(PARALLEL_FETCHES)
        .collect()
        .await;
    let mut body = Vec::new();
    for (meta, blob) in page.chunks.iter().zip(blobs) {
        api::batch::encode_frame(&mut body, meta.seq, &meta.chunk_id, &blob?)
            .map_err(|e| ApiErr::internal("batch", e))?;
    }
    Ok(binary(
        body,
        &[
            ("x-max-seq", page.max_seq.to_string()),
            ("x-has-more", page.has_more.to_string()),
        ],
    ))
}

async fn get_chunk(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path((vault_id, seq)): Path<(String, u64)>,
) -> ApiResult<Response> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    let (meta, keys) = state
        .run(move |state| {
            let (store, keys) = state.open_store_with_keys(&auth.account)?;
            Ok((store.chunk(&vault_id, seq)?, keys))
        })
        .await?;
    Ok(binary(
        fetch_chunk(&state, &keys, &meta.object_id).await?,
        &[],
    ))
}

async fn compact(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    Json(request): Json<CompactRequest>,
) -> ApiResult<StatusCode> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    if request.chunk_ids.is_empty() || request.chunk_ids.len() > 10_000 {
        return Err(ApiErr::bad_request(
            "chunkIds must list 1 to 10000 replacement chunks.",
        ));
    }
    state
        .run(move |state| {
            let (mut store, keys) = state.open_store_with_keys(&auth.account)?;
            let removed =
                store.compact(&vault_id, request.replaces_up_to_seq, &request.chunk_ids)?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            state.enqueue_object_deletions(&keys, &removed)?;
            Ok(())
        })
        .await?;
    state.kick_deletions();
    Ok(StatusCode::NO_CONTENT)
}

async fn get_live(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
) -> ApiResult<Response> {
    auth.require_sync(Scope::Sync)?;
    let vault_id = parse_vault(&vault_id)?;
    let Some(snapshot) =
        state.live_snapshot(auth.account.account_id.as_str(), &vault_id.to_string())
    else {
        return Err(ApiErr::not_found(
            codes::LIVE_NOT_FOUND,
            "No live snapshot is available for this vault.",
        ));
    };
    let age = now_ms().saturating_sub(snapshot.published_at_ms).max(0) / 1000;
    Ok(binary(
        snapshot.blob,
        &[
            (headers::LIVE_SEQ, snapshot.seq.to_string()),
            (headers::LIVE_AGE, age.to_string()),
        ],
    ))
}

pub(crate) async fn publish_live(
    State(state): State<Shared>,
    Path((account_id, vault_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let account_id: AccountId = account_id
        .parse()
        .map_err(|_| ApiErr::bad_request("Invalid account id."))?;
    let vault_id = parse_vault(&vault_id)?;
    let seq = header_u64(&headers, headers::LIVE_SEQ)?;
    if body.len() < vrcx_0_nanashi_website_protocol::seal::OVERHEAD || body.len() > 1024 * 1024 {
        return Err(ApiErr::bad_request("Invalid live snapshot size."));
    }
    let blob = body.to_vec();
    state
        .run(move |state| {
            let account = state
                .registry()
                .account(&account_id)?
                .ok_or_else(|| ApiErr::not_found(codes::VAULT_NOT_FOUND, "Account not found."))?;
            if account.state != AccountState::Active
                || !account.sync_allowed
                || !account.collector_allowed
            {
                return Err(ApiErr::feature_disabled(
                    "Collector is disabled for this account.",
                ));
            }
            let store = state.open_store(&account)?;
            if store.manifest(&vault_id)?.is_none() {
                return Err(ApiErr::not_found(
                    codes::MANIFEST_NOT_FOUND,
                    "Vault manifest not found.",
                ));
            }
            if state.publish_live_snapshot(account_id.as_str(), &vault_id.to_string(), seq, blob) {
                Ok(StatusCode::NO_CONTENT)
            } else {
                Err(ApiErr::new(
                    StatusCode::CONFLICT,
                    codes::MANIFEST_SEQ_CONFLICT,
                    "Live sequence must increase.",
                ))
            }
        })
        .await
}

pub(crate) async fn delete_live(
    State(state): State<Shared>,
    Path((account_id, vault_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let account_id: AccountId = account_id
        .parse()
        .map_err(|_| ApiErr::bad_request("Invalid account id."))?;
    let vault_id = parse_vault(&vault_id)?;
    state.clear_live_snapshot(account_id.as_str(), Some(&vault_id.to_string()));
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn collector_store_chunk(
    State(state): State<Shared>,
    Path((account_id, vault_id, chunk_id)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<ChunkStored>)> {
    let account_id: AccountId = account_id
        .parse()
        .map_err(|_| ApiErr::bad_request("Invalid account id."))?;
    let vault_id = parse_vault(&vault_id)?;
    let chunk_id: ChunkId = chunk_id
        .parse()
        .map_err(|_| ApiErr::bad_request("Invalid chunk id."))?;
    if body.is_empty() || body.len() > api::MAX_CHUNK_BYTES {
        return Err(ApiErr::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::TOO_LARGE,
            "Chunk is empty or too large.",
        ));
    }
    let blob_hash: [u8; 32] = Sha256::digest(&body).into();
    let size = body.len() as u64;
    let account = state
        .run(move |state| {
            let account = state
                .registry()
                .account(&account_id)?
                .ok_or_else(|| ApiErr::not_found(codes::VAULT_NOT_FOUND, "Account not found."))?;
            if account.state != AccountState::Active
                || !account.sync_allowed
                || !account.collector_allowed
            {
                return Err(ApiErr::feature_disabled(
                    "Collector is disabled for this account.",
                ));
            }
            let store = state.open_store(&account)?;
            if store.manifest(&vault_id)?.is_none() {
                return Err(ApiErr::not_found(
                    codes::MANIFEST_NOT_FOUND,
                    "Vault manifest not found.",
                ));
            }
            Ok(account)
        })
        .await?;
    let upload = state
        .run({
            let account = account.clone();
            let body = body.to_vec();
            move |state| {
                let (store, keys) = state.open_store_with_keys(&account)?;
                match store.check_chunk(
                    &vault_id,
                    &chunk_id,
                    &blob_hash,
                    size,
                    AppState::limits(&account),
                )? {
                    ChunkCheck::Existing(seq) => Ok(Upload::Done(seq)),
                    ChunkCheck::New => {
                        let object_id: ObjectId = crate::util::random_bytes();
                        let key = keys.object_key(&object_id);
                        let sealed = keys.seal_object(&key, &body);
                        Ok(Upload::Store {
                            object_id,
                            key,
                            sealed,
                        })
                    }
                }
            }
        })
        .await?;
    let (object_id, key, sealed) = match upload {
        Upload::Done(seq) => return Ok((StatusCode::CREATED, Json(ChunkStored { seq }))),
        Upload::Store {
            object_id,
            key,
            sealed,
        } => (object_id, key, sealed),
    };
    state
        .objects
        .put(&key, sealed)
        .await
        .map_err(ApiErr::storage)?;
    let insert = state
        .run(move |state| {
            let (mut store, keys) = state.open_store_with_keys(&account)?;
            let result = store.insert_chunk(
                &vault_id,
                &NewChunk {
                    chunk_id: &chunk_id,
                    object_id,
                    blob_hash,
                    size,
                },
                AppState::limits(&account),
            );
            match result {
                Ok((seq, duplicate)) => {
                    if duplicate {
                        state.enqueue_object_deletions(&keys, &[object_id])?;
                    }
                    state.refresh_usage(&account.account_id, &store)?;
                    Ok(seq)
                }
                Err(error) => {
                    state.enqueue_object_deletions(&keys, &[object_id])?;
                    Err(error.into())
                }
            }
        })
        .await;
    if insert.is_err() {
        state.kick_deletions();
    }
    Ok((StatusCode::CREATED, Json(ChunkStored { seq: insert? })))
}

async fn collector_capabilities(state: &Shared) -> Option<CollectorCapabilities> {
    let (status, body) = crate::uds::call(
        &state.config.collector_socket,
        Method::GET,
        "/capabilities",
        Vec::new(),
        false,
    )
    .await
    .ok()?;
    if !status.is_success() {
        return None;
    }
    serde_json::from_slice::<CollectorCapabilities>(&body)
        .ok()
        .filter(|capabilities| capabilities.available)
}

fn require_collector(auth: &ApiAuth) -> ApiResult<()> {
    auth.require_sync(Scope::Collector)?;
    if !auth.account.collector_allowed {
        return Err(ApiErr::feature_disabled(
            "Collector is disabled for this account.",
        ));
    }
    Ok(())
}

async fn collector_status(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
) -> ApiResult<Response> {
    require_collector(&auth)?;
    let vault_id = parse_vault(&vault_id)?;
    collector_proxy(
        &state,
        Method::GET,
        &format!("/status/{}/{}", auth.account.account_id, vault_id),
        Vec::new(),
    )
    .await
}

async fn collector_unlock(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    require_collector(&auth)?;
    let vault_id = parse_vault(&vault_id)?;
    if body.len() < vrcx_0_nanashi_website_protocol::seal::OVERHEAD
        || body.len() > vrcx_0_nanashi_website_protocol::api::MAX_REQUEST_BYTES
    {
        return Err(ApiErr::bad_request(
            "Invalid sealed collector unlock payload.",
        ));
    }
    collector_proxy(
        &state,
        Method::POST,
        &format!("/unlock/{}/{}", auth.account.account_id, vault_id),
        body.to_vec(),
    )
    .await
}

async fn collector_lock(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(vault_id): Path<String>,
) -> ApiResult<Response> {
    require_collector(&auth)?;
    let vault_id = parse_vault(&vault_id)?;
    collector_proxy(
        &state,
        Method::POST,
        &format!("/lock/{}/{}", auth.account.account_id, vault_id),
        Vec::new(),
    )
    .await
}

async fn collector_proxy(
    state: &Shared,
    method: Method,
    uri: &str,
    body: Vec<u8>,
) -> ApiResult<Response> {
    let (status, body) = crate::uds::call(&state.config.collector_socket, method, uri, body, false)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "collector control socket unavailable");
            ApiErr::new(
                StatusCode::SERVICE_UNAVAILABLE,
                codes::COLLECTOR_UNAVAILABLE,
                "The collector is not running on this server.",
            )
        })?;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    Ok(response)
}

pub(crate) async fn lock_collector_account(state: &Shared, account_id: &str) {
    let _ = crate::uds::call(
        &state.config.collector_socket,
        Method::POST,
        &format!("/lock-account/{account_id}"),
        Vec::new(),
        false,
    )
    .await;
    state.clear_live_snapshot(account_id, None);
}

async fn transfer_create(
    State(state): State<Shared>,
    auth: ApiAuth,
    Json(request): Json<TransferCreateRequest>,
) -> ApiResult<(StatusCode, Json<TransferCreated>)> {
    auth.require_sync_enabled()?;
    let epk =
        b64::decode(&request.epk).map_err(|_| ApiErr::bad_request("epk is not base64url."))?;
    SealPublicKey::from_bytes(&epk)
        .map_err(|_| ApiErr::bad_request("epk is not an X25519 public key."))?;
    state
        .run(move |state| {
            let registry = state.registry();
            registry.prune_expired(auth.now_ms)?;
            let transfer_id =
                transfer::new_transfer_id().map_err(|e| ApiErr::internal("rng", e))?;
            registry.insert_transfer(
                &transfer_id,
                &auth.account.account_id,
                &epk,
                auth.now_ms + TRANSFER_TTL_MS,
            )?;
            Ok((
                StatusCode::CREATED,
                Json(TransferCreated {
                    transfer_id,
                    expires_in: (TRANSFER_TTL_MS / 1000) as u32,
                }),
            ))
        })
        .await
}

fn transfer_not_found() -> ApiErr {
    ApiErr::not_found(codes::TRANSFER_NOT_FOUND, "Transfer not found or expired.")
}

async fn transfer_key(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(transfer_id): Path<String>,
) -> ApiResult<Json<TransferKey>> {
    auth.require_sync_enabled()?;
    transfer::validate_transfer_id(&transfer_id).map_err(|_| transfer_not_found())?;
    state
        .run(move |state| {
            let (epk, _) = state
                .registry()
                .transfer(&transfer_id, &auth.account.account_id, auth.now_ms)?
                .ok_or_else(transfer_not_found)?;
            Ok(Json(TransferKey {
                epk: b64::encode(&epk),
            }))
        })
        .await
}

async fn transfer_complete(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(transfer_id): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    auth.require_sync_enabled()?;
    auth.require_recent_auth_on_web()?;
    transfer::validate_transfer_id(&transfer_id).map_err(|_| transfer_not_found())?;
    if body.is_empty() || body.len() > 1024 {
        return Err(ApiErr::bad_request(
            "Sealed secret must be 1 to 1024 bytes.",
        ));
    }
    state
        .run(move |state| {
            let registry = state.registry();
            if !registry.complete_transfer(
                &transfer_id,
                &auth.account.account_id,
                &body,
                auth.now_ms,
            )? {
                return Err(transfer_not_found());
            }
            registry.audit(
                &auth.token.token_id,
                "key-transfer",
                Some(&auth.account.account_id),
                auth.now_ms,
            )?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn transfer_result(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(transfer_id): Path<String>,
) -> ApiResult<Response> {
    auth.require_sync_enabled()?;
    transfer::validate_transfer_id(&transfer_id).map_err(|_| transfer_not_found())?;
    state
        .run(move |state| {
            let registry = state.registry();
            let (_, sealed) = registry
                .transfer(&transfer_id, &auth.account.account_id, auth.now_ms)?
                .ok_or_else(transfer_not_found)?;
            match sealed {
                Some(sealed) => {
                    registry.delete_transfer(&transfer_id)?;
                    Ok(binary(sealed, &[]))
                }
                None => Err(ApiErr::pending(
                    codes::AUTHORIZATION_PENDING,
                    "Waiting for the other device.",
                )),
            }
        })
        .await
}

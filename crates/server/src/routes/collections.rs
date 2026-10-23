use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use vrcx_0_nanashi_website_protocol::api::{CollectionSnapshot, Scope, codes};
use vrcx_0_nanashi_website_protocol::token;

use crate::auth::ApiAuth;
use crate::db::account::{AccountStore, StoreError};
use crate::db::registry::AccountRow;
use crate::http::{ApiErr, ApiResult};
use crate::state::{AppState, Shared};
use crate::util::now_epoch;

const MAX_COLLECTIONS: i64 = 100;
const MAX_WORLDS: usize = 500;
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub fn public_router() -> Router<Shared> {
    Router::new()
        .route("/collections", get(directory))
        .route("/collections/{code}", get(public_get))
        .fallback(crate::routes::api_not_found)
}

fn normalize_code(code: &str) -> ApiResult<String> {
    if code.len() != 8 || !code.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(collection_not_found());
    }
    Ok(code.to_ascii_uppercase())
}

fn collection_not_found() -> ApiErr {
    ApiErr::not_found(codes::COLLECTION_NOT_FOUND, "Collection not found.")
}

fn validate(snapshot: &CollectionSnapshot) -> ApiResult<()> {
    let field = |value: &str, max: usize| value.chars().count() <= max;
    if snapshot.title.trim().is_empty()
        || !field(&snapshot.title, 120)
        || snapshot.note.as_deref().is_some_and(|v| !field(v, 2000))
        || !field(&snapshot.author_name, 120)
        || snapshot
            .author_profile
            .as_deref()
            .is_some_and(|v| !v.is_empty() && !v.starts_with("https://"))
        || snapshot.category.as_deref().is_some_and(|v| !field(v, 80))
        || snapshot.worlds.len() > MAX_WORLDS
    {
        return Err(ApiErr::bad_request(
            "Collection fields exceed their limits or the title is empty.",
        ));
    }
    for world in &snapshot.worlds {
        if !world.world_id.starts_with("wrld_")
            || !field(&world.world_id, 128)
            || !field(&world.name, 200)
            || !field(&world.author_name, 200)
            || !field(&world.description, 4000)
            || !field(&world.comment, 2000)
            || !world.image_url.is_empty()
                && !["https://api.vrchat.cloud/", "https://assets.vrchat.com/"]
                    .iter()
                    .any(|prefix| world.image_url.starts_with(prefix))
        {
            return Err(ApiErr::bad_request(
                "A world entry has invalid fields or an unsupported image URL.",
            ));
        }
    }
    Ok(())
}

fn parse_collection_rows(rows: Vec<String>) -> ApiResult<Vec<CollectionSnapshot>> {
    rows.into_iter()
        .map(|body| {
            serde_json::from_str(&body).map_err(|error| ApiErr::internal("collection data", error))
        })
        .collect()
}

fn owned_store(state: &AppState, account: &AccountRow) -> ApiResult<AccountStore> {
    state.open_store(account)
}

pub async fn list_owned(
    auth: ApiAuth,
    State(state): State<Shared>,
) -> ApiResult<Json<Vec<CollectionSnapshot>>> {
    auth.require(Scope::Share)?;
    state
        .run(move |state| {
            let store = owned_store(state, &auth.account)?;
            Ok(Json(parse_collection_rows(store.collections()?)?))
        })
        .await
}

pub async fn create(
    State(state): State<Shared>,
    auth: ApiAuth,
    Json(mut snapshot): Json<CollectionSnapshot>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    auth.require(Scope::Share)?;
    validate(&snapshot)?;
    snapshot.updated_at = now_epoch();
    let out = state
        .run(move |state| {
            let store = owned_store(state, &auth.account)?;
            let mut store = store;
            let mut selected = None;
            for _ in 0..8 {
                let code = token::generate_user_code()
                    .map_err(|error| ApiErr::internal("rng", error))?
                    .replace('-', "");
                if state.registry().collection_owner(&code)?.is_none() {
                    selected = Some(code);
                    break;
                }
            }
            let code = selected.ok_or_else(|| {
                ApiErr::internal("rng", "could not allocate a unique collection code")
            })?;
            snapshot.id = code.clone();
            let body = serde_json::to_string(&snapshot)
                .map_err(|error| ApiErr::internal("collection encode", error))?;
            if body.len() > MAX_BODY_BYTES {
                return Err(ApiErr::bad_request("Collection data is too large."));
            }
            store
                .put_collection(
                    &code,
                    &body,
                    now_epoch(),
                    AppState::limits(&auth.account),
                    MAX_COLLECTIONS,
                )
                .map_err(|error| {
                    if matches!(error, StoreError::Invalid("collection limit reached")) {
                        ApiErr::new(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "collection_limit",
                            error.to_string(),
                        )
                    } else {
                        ApiErr::from(error)
                    }
                })?;
            state.registry().set_collection_index(
                &auth.account.account_id,
                &code,
                snapshot.listed,
                if snapshot.listed { &snapshot.title } else { "" },
                if snapshot.listed {
                    snapshot.category.as_deref()
                } else {
                    None
                },
                now_epoch(),
            )?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            let origin = state
                .config
                .web_origins
                .first()
                .cloned()
                .unwrap_or_default();
            Ok(serde_json::json!({ "code": code, "url": format!("{origin}/c/{code}") }))
        })
        .await?;
    Ok((StatusCode::CREATED, Json(out)))
}

pub async fn get_owned(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(code): Path<String>,
) -> ApiResult<Json<CollectionSnapshot>> {
    auth.require(Scope::Share)?;
    let code = normalize_code(&code)?;
    state
        .run(move |state| {
            if state.registry().collection_owner(&code)?.as_ref() != Some(&auth.account.account_id)
            {
                return Err(collection_not_found());
            }
            let store = owned_store(state, &auth.account)?;
            let body = store.collection(&code)?.ok_or_else(collection_not_found)?;
            Ok(Json(serde_json::from_str(&body).map_err(|error| {
                ApiErr::internal("collection data", error)
            })?))
        })
        .await
}

pub async fn update(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(code): Path<String>,
    Json(mut snapshot): Json<CollectionSnapshot>,
) -> ApiResult<Json<CollectionSnapshot>> {
    auth.require(Scope::Share)?;
    let code = normalize_code(&code)?;
    validate(&snapshot)?;
    snapshot.id = code.clone();
    snapshot.updated_at = now_epoch();
    let body = serde_json::to_string(&snapshot)
        .map_err(|error| ApiErr::internal("collection encode", error))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiErr::bad_request("Collection data is too large."));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiErr::bad_request("Collection data is too large."));
    }
    state
        .run(move |state| {
            if state.registry().collection_owner(&code)?.as_ref() != Some(&auth.account.account_id)
            {
                return Err(collection_not_found());
            }
            let mut store = owned_store(state, &auth.account)?;
            if store.collection(&code)?.is_none() {
                return Err(collection_not_found());
            }
            store
                .put_collection(
                    &code,
                    &body,
                    now_epoch(),
                    AppState::limits(&auth.account),
                    MAX_COLLECTIONS,
                )
                .map_err(ApiErr::from)?;
            state.registry().set_collection_index(
                &auth.account.account_id,
                &code,
                snapshot.listed,
                if snapshot.listed { &snapshot.title } else { "" },
                if snapshot.listed {
                    snapshot.category.as_deref()
                } else {
                    None
                },
                now_epoch(),
            )?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            Ok(Json(snapshot))
        })
        .await
}

pub async fn delete(
    State(state): State<Shared>,
    auth: ApiAuth,
    Path(code): Path<String>,
) -> ApiResult<StatusCode> {
    auth.require(Scope::Share)?;
    let code = normalize_code(&code)?;
    state
        .run(move |state| {
            if state.registry().collection_owner(&code)?.as_ref() != Some(&auth.account.account_id)
            {
                return Err(collection_not_found());
            }
            let mut store = owned_store(state, &auth.account)?;
            if !store.delete_collection(&code)? {
                return Err(collection_not_found());
            }
            state
                .registry()
                .delete_collection_index(&auth.account.account_id, &code)?;
            state.refresh_usage(&auth.account.account_id, &store)?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

#[derive(Deserialize, Default)]
struct DirectoryQuery {
    q: Option<String>,
    category: Option<String>,
    before: Option<i64>,
    listed: Option<bool>,
}

async fn directory(
    State(state): State<Shared>,
    Query(query): Query<DirectoryQuery>,
) -> ApiResult<Json<Vec<Value>>> {
    state
        .run(move |state| {
            let q = query.q.unwrap_or_default().to_lowercase();
            let category = query.category.unwrap_or_default().to_lowercase();
            let before = query.before;
            if query.listed == Some(false) {
                return Ok(Json(Vec::new()));
            }
            let rows = state.registry().listed_collections()?;
            let result = rows
                .into_iter()
                .filter(|(_, _, title, cat, _)| {
                    (q.is_empty() || title.to_lowercase().contains(&q))
                        && (category.is_empty()
                            || cat.as_deref().unwrap_or_default().to_lowercase() == category)
                })
                .filter(|(_, _, _, _, updated_at)| before.is_none_or(|cursor| *updated_at < cursor))
                .take(100)
                .map(|(code, _owner, title, category, updated_at)| {
                    serde_json::json!({
                        "id": code, "title": title, "category": category, "updated_at": updated_at,
                    })
                })
                .collect();
            Ok(Json(result))
        })
        .await
}

async fn public_get(
    State(state): State<Shared>,
    Path(code): Path<String>,
) -> ApiResult<Json<CollectionSnapshot>> {
    let code = normalize_code(&code)?;
    state
        .run(move |state| {
            let owner = state
                .registry()
                .collection_owner(&code)?
                .ok_or_else(collection_not_found)?;
            let account = state
                .registry()
                .account(&owner)?
                .ok_or_else(collection_not_found)?;
            let store = owned_store(state, &account)?;
            let body = store.collection(&code)?.ok_or_else(collection_not_found)?;
            Ok(Json(serde_json::from_str(&body).map_err(|error| {
                ApiErr::internal("collection data", error)
            })?))
        })
        .await
}

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use vrcx_0_nanashi_website_protocol::api::{ApiError, codes};

use crate::db::DbError;
use crate::db::account::StoreError;

#[derive(Debug)]
pub struct ApiErr {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retry_after: Option<u64>,
}

pub type ApiResult<T> = Result<T, ApiErr>;

impl ApiErr {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            codes::UNAUTHORIZED,
            "Missing, unknown, revoked, or expired token.",
        )
    }

    pub fn forbidden_scope() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN_SCOPE,
            "This token does not have the required scope.",
        )
    }

    pub fn feature_disabled(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, codes::FEATURE_DISABLED, message)
    }

    pub fn sync_disabled() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            codes::SYNC_DISABLED,
            "RemoteSync was disabled for this account by an administrator.",
        )
    }

    pub fn storage(error: crate::objects::ObjectError) -> Self {
        tracing::error!("{error}");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            codes::STORAGE_UNAVAILABLE,
            "Storage is temporarily unavailable. Try again later.",
        )
    }

    pub fn reauth_required() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            codes::REAUTH_REQUIRED,
            "Enter a 2FA code first (POST /v2/account/reauth).",
        )
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    pub fn pending(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn rate_limited(retry_after: u64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            codes::RATE_LIMITED,
            "Too many requests.",
        );
        error.retry_after = Some(retry_after);
        error
    }

    pub fn internal(context: &str, error: impl std::fmt::Display) -> Self {
        tracing::error!("{context}: {error}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "Internal error.",
        )
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let mut response =
            (self.status, Json(ApiError::new(self.code, self.message))).into_response();
        if let Some(seconds) = self.retry_after
            && let Ok(value) = seconds.to_string().parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}

impl From<DbError> for ApiErr {
    fn from(error: DbError) -> Self {
        Self::internal("database", error)
    }
}

impl From<StoreError> for ApiErr {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::VaultNotFound => {
                Self::not_found(codes::VAULT_NOT_FOUND, "Vault not found.")
            }
            StoreError::ChunkNotFound => {
                Self::not_found(codes::CHUNK_NOT_FOUND, "Chunk not found.")
            }
            StoreError::VaultExists => Self::new(
                StatusCode::CONFLICT,
                codes::VAULT_EXISTS,
                "Vault already exists.",
            ),
            StoreError::VaultLimit => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                codes::QUOTA_EXCEEDED,
                "This account has reached its vault limit.",
            ),
            StoreError::ChunkIdExists => Self::new(
                StatusCode::CONFLICT,
                codes::CHUNK_ID_EXISTS,
                "Chunk id already used with different contents.",
            ),
            StoreError::ManifestConflict => Self::new(
                StatusCode::CONFLICT,
                codes::MANIFEST_SEQ_CONFLICT,
                "Manifest sequence does not follow the stored one.",
            ),
            StoreError::QuotaExceeded => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                codes::QUOTA_EXCEEDED,
                "This upload would exceed the account's database size limit.",
            ),
            StoreError::Invalid(message) => Self::bad_request(message),
            StoreError::Db(error) => Self::from(error),
        }
    }
}

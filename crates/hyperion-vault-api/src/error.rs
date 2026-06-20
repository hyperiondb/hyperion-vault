use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::store::StoreError;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    Forbidden,
    TooManyRequests,
    NotFound,
    BadRequest(String),
    Conflict(String),
    Internal(anyhow::Error),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, String) {
        match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            ApiError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts; locked out".to_string(),
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ApiError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(ref err) = self {
            tracing::error!(error = %err, "internal error");
        }
        let (status, message) = self.parts();
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err)
    }
}

impl From<hyperion_vault_core::Error> for ApiError {
    fn from(err: hyperion_vault_core::Error) -> Self {
        ApiError::Internal(anyhow::Error::new(err))
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound => ApiError::NotFound,
            StoreError::Conflict(msg) => ApiError::Conflict(msg),
            StoreError::VersionConflict => {
                ApiError::Conflict("write conflict; retry the request".to_string())
            }
            StoreError::Internal(err) => ApiError::Internal(err),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    Forbidden,
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

impl From<tokio_postgres::Error> for ApiError {
    fn from(err: tokio_postgres::Error) -> Self {
        ApiError::Internal(anyhow::Error::new(err))
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        ApiError::Internal(anyhow::Error::new(err))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

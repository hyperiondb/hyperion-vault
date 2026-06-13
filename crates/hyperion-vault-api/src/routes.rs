use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::dto::{
    CreateSecretRequest, SecretMetadata, SecretValue, UpdateSecretRequest, VerifyRequest,
    VerifyResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::guards::{AdminActor, ReaderGuard};
use crate::service;
use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/secrets", post(create_secret).get(list_secrets))
        .route(
            "/v1/secrets/{name}",
            get(get_secret).put(update_secret).delete(delete_secret),
        )
        .route("/v1/secrets/{name}/rotate", post(rotate_secret))
        .route("/v1/secrets/{name}/verify", post(verify_secret))
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn create_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Json(req): Json<CreateSecretRequest>,
) -> ApiResult<(StatusCode, Json<SecretValue>)> {
    let value = service::create_secret(&state, &actor.0, req).await?;
    Ok((StatusCode::CREATED, Json(value)))
}

async fn list_secrets(
    State(state): State<SharedState>,
    _actor: AdminActor,
) -> ApiResult<Json<Vec<SecretMetadata>>> {
    Ok(Json(service::list_secrets(&state).await?))
}

async fn get_secret(
    State(state): State<SharedState>,
    guard: ReaderGuard,
    Path(name): Path<String>,
) -> ApiResult<Json<SecretValue>> {
    Ok(Json(service::get_secret(&state, &name, guard.client_ip).await?))
}

async fn update_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
    Json(req): Json<UpdateSecretRequest>,
) -> ApiResult<Json<SecretMetadata>> {
    Ok(Json(service::update_secret(&state, &actor.0, &name, req).await?))
}

async fn delete_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    service::delete_secret(&state, &actor.0, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<Json<SecretValue>> {
    Ok(Json(service::rotate(&state, &actor.0, None, &name).await?))
}

async fn verify_secret(
    State(state): State<SharedState>,
    guard: ReaderGuard,
    Path(name): Path<String>,
    Json(req): Json<VerifyRequest>,
) -> ApiResult<Json<VerifyResponse>> {
    Ok(Json(
        service::verify(&state, &name, guard.client_ip, &req.value).await?,
    ))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<SharedState>) -> Result<&'static str, ApiError> {
    let client = state.db.reader().await?;
    client.simple_query("SELECT 1").await?;
    Ok("ready")
}

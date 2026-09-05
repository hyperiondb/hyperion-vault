use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::dto::{
    BatchGetRequest, CreateRoleRequest, CreateSecretRequest, CreateTokenRequest, RewrapRunResponse,
    RewrapStatusResponse, RoleInfo, SecretMetadata, SecretValue, SetPermissionsRequest,
    TokenCreated, TokenInfo, UpdateSecretRequest, VerifyRequest,
};
use crate::error::{ApiError, ApiResult};
use crate::guards::{AdminActor, ReaderGuard};
use crate::state::SharedState;
use crate::store::BackupData;
use crate::{authz, manage, rewrap, service};

const RESTORE_BODY_LIMIT: usize = 256 << 20;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/secrets", post(create_secret).get(list_secrets))
        .route(
            "/v1/secrets/{*name}",
            get(get_secret)
                .put(update_secret)
                .delete(delete_secret)
                .post(secret_action),
        )
        .route("/v1/batch/secrets", post(batch_get_secrets))
        .route("/v1/roles", post(create_role).get(list_roles))
        .route("/v1/roles/{name}", get(get_role).delete(delete_role))
        .route("/v1/roles/{name}/permissions", put(set_permissions))
        .route("/v1/tokens", post(create_token).get(list_tokens))
        .route("/v1/tokens/{name}", delete(revoke_token))
        .route("/v1/backup", get(backup))
        .route(
            "/v1/restore",
            post(restore).layer(DefaultBodyLimit::max(RESTORE_BODY_LIMIT)),
        )
        .route("/v1/admin/kms/rewrap", post(kms_rewrap))
        .route("/v1/admin/kms/rewrap/status", get(kms_rewrap_status))
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn create_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Json(req): Json<CreateSecretRequest>,
) -> ApiResult<(StatusCode, Json<SecretValue>)> {
    authz::authorize(&state, &actor, "create", &req.name).await?;
    authz::authorize_rotation_target(&state, &actor, &req).await?;
    let value = service::create_secret(&state, &actor.name, req).await?;
    Ok((StatusCode::CREATED, Json(value)))
}

async fn list_secrets(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<Vec<SecretMetadata>>> {
    let all = service::list_secrets(&state).await?;
    let visible = all
        .into_iter()
        .filter(|m| hyperion_vault_core::rbac::visible(actor.is_admin, &actor.rules, &m.name))
        .collect();
    Ok(Json(visible))
}

async fn get_secret(
    State(state): State<SharedState>,
    guard: ReaderGuard,
    Path(name): Path<String>,
) -> ApiResult<Json<SecretValue>> {
    Ok(Json(
        service::get_secret(&state, &name, guard.client_ip).await?,
    ))
}

async fn batch_get_secrets(
    State(state): State<SharedState>,
    guard: ReaderGuard,
    Json(req): Json<BatchGetRequest>,
) -> ApiResult<Json<Vec<SecretValue>>> {
    Ok(Json(
        service::get_secrets(&state, req.names, guard.client_ip).await?,
    ))
}

async fn update_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
    Json(req): Json<UpdateSecretRequest>,
) -> ApiResult<Json<SecretMetadata>> {
    authz::authorize(&state, &actor, "update", &name).await?;
    Ok(Json(
        service::update_secret(&state, &actor.name, &name, req).await?,
    ))
}

async fn delete_secret(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    authz::authorize(&state, &actor, "delete", &name).await?;
    service::delete_secret(&state, &actor.name, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

// A secret name may contain '/', so the route captures the whole remaining path
// and the action is the last segment: "db/password/rotate" rotates "db/password".
async fn secret_action(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let (name, action) = path.rsplit_once('/').ok_or(ApiError::NotFound)?;
    let (mut parts, body) = request.into_parts();

    match action {
        "rotate" => {
            let actor = AdminActor::from_request_parts(&mut parts, &state).await?;
            authz::authorize(&state, &actor, "rotate", name).await?;
            let value = service::rotate(&state, &actor.name, None, name).await?;
            Ok(Json(value).into_response())
        }
        "verify" => {
            let guard = ReaderGuard::from_request_parts(&mut parts, &state).await?;
            let request = Request::from_parts(parts, body);
            let Json(req) = Json::<VerifyRequest>::from_request(request, &state)
                .await
                .map_err(|err| ApiError::BadRequest(err.body_text()))?;
            let response =
                service::verify(&state, name, guard.client_ip, guard.peer_ip, &req.value).await?;
            Ok(Json(response).into_response())
        }
        _ => Err(ApiError::NotFound),
    }
}

async fn create_role(
    State(state): State<SharedState>,
    actor: AdminActor,
    Json(req): Json<CreateRoleRequest>,
) -> ApiResult<(StatusCode, Json<RoleInfo>)> {
    authz::require_admin(&state, &actor).await?;
    Ok((
        StatusCode::CREATED,
        Json(manage::create_role(&state, req).await?),
    ))
}

async fn list_roles(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<Vec<RoleInfo>>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(manage::list_roles(&state).await?))
}

async fn get_role(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<Json<RoleInfo>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(manage::get_role(&state, &name).await?))
}

async fn set_permissions(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
    Json(req): Json<SetPermissionsRequest>,
) -> ApiResult<Json<RoleInfo>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(
        manage::set_permissions(&state, &name, req.permissions).await?,
    ))
}

async fn delete_role(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    authz::require_admin(&state, &actor).await?;
    manage::delete_role(&state, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_token(
    State(state): State<SharedState>,
    actor: AdminActor,
    Json(req): Json<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<TokenCreated>)> {
    authz::require_admin(&state, &actor).await?;
    Ok((
        StatusCode::CREATED,
        Json(manage::create_token(&state, req).await?),
    ))
}

async fn list_tokens(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<Vec<TokenInfo>>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(manage::list_tokens(&state).await?))
}

async fn revoke_token(
    State(state): State<SharedState>,
    actor: AdminActor,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    authz::require_admin(&state, &actor).await?;
    manage::revoke_token(&state, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn backup(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<BackupData>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(manage::backup(&state, &actor.name).await?))
}

async fn restore(
    State(state): State<SharedState>,
    actor: AdminActor,
    Json(data): Json<BackupData>,
) -> ApiResult<StatusCode> {
    authz::require_admin(&state, &actor).await?;
    manage::restore(&state, &actor.name, data).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn kms_rewrap(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<RewrapRunResponse>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(
        rewrap::force(&state).await.map_err(ApiError::Internal)?,
    ))
}

async fn kms_rewrap_status(
    State(state): State<SharedState>,
    actor: AdminActor,
) -> ApiResult<Json<RewrapStatusResponse>> {
    authz::require_admin(&state, &actor).await?;
    Ok(Json(
        rewrap::status(&state).await.map_err(ApiError::Internal)?,
    ))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<SharedState>) -> Result<&'static str, ApiError> {
    state.store.list_roles().await?;
    Ok("ready")
}

use hyperion_vault_core::rbac;

use crate::dto::CreateSecretRequest;
use crate::error::{ApiError, ApiResult};
use crate::guards::AdminActor;
use crate::lockout;
use crate::state::AppState;
use crate::store::RotationTarget;

pub async fn authorize(
    state: &AppState,
    actor: &AdminActor,
    action: &str,
    name: &str,
) -> ApiResult<()> {
    if rbac::authorize(actor.is_admin, &actor.rules, action, name) {
        Ok(())
    } else {
        lockout::record(state, actor.peer_ip).await;
        Err(ApiError::Forbidden)
    }
}

pub async fn authorize_rotation_target(
    state: &AppState,
    actor: &AdminActor,
    req: &CreateSecretRequest,
) -> ApiResult<()> {
    let Some(RotationTarget::PgReplica(pg)) = req.target.as_ref() else {
        return Ok(());
    };

    if let Some(login) = &pg.login_secret {
        if !rbac::visible(actor.is_admin, &actor.rules, login) {
            lockout::record(state, actor.peer_ip).await;
            return Err(ApiError::Forbidden);
        }
    }

    if let Some(role) = &pg.role {
        let username = req.username.as_deref().unwrap_or_default();
        if !actor.is_admin && role != username {
            lockout::record(state, actor.peer_ip).await;
            return Err(ApiError::Forbidden);
        }
    }

    Ok(())
}

pub async fn require_admin(state: &AppState, actor: &AdminActor) -> ApiResult<()> {
    if actor.is_admin {
        Ok(())
    } else {
        lockout::record(state, actor.peer_ip).await;
        Err(ApiError::Forbidden)
    }
}

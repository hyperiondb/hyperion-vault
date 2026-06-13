use hyperion_vault_core::rbac;

use crate::error::{ApiError, ApiResult};
use crate::guards::AdminActor;
use crate::lockout;
use crate::state::AppState;

pub async fn authorize(
    state: &AppState,
    actor: &AdminActor,
    action: &str,
    name: &str,
) -> ApiResult<()> {
    if rbac::authorize(actor.is_admin, &actor.rules, action, name) {
        Ok(())
    } else {
        lockout::record(state, actor.client_ip).await;
        Err(ApiError::Forbidden)
    }
}

pub async fn require_admin(state: &AppState, actor: &AdminActor) -> ApiResult<()> {
    if actor.is_admin {
        Ok(())
    } else {
        lockout::record(state, actor.client_ip).await;
        Err(ApiError::Forbidden)
    }
}

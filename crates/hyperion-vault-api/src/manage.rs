use hyperion_vault_core::{auth, rbac};

use crate::clock::{now_unix, rfc3339, rfc3339_opt};
use crate::dto::{
    CreateRoleRequest, CreateTokenRequest, PermissionRule, RoleInfo, TokenCreated, TokenInfo,
};
use crate::error::{ApiError, ApiResult};
use crate::service::audit;
use crate::state::AppState;
use crate::store::backup::BACKUP_VERSION;
use crate::store::{BackupData, Command, RoleRecord, TokenRecord};

const BUILTIN_ADMIN_ROLE: &str = "admin";

pub async fn backup(state: &AppState, actor: &str) -> ApiResult<BackupData> {
    let data = state.store.dump().await?;
    audit(state, Some(actor), None, "backup", None, "ok").await;
    Ok(data)
}

pub async fn restore(state: &AppState, actor: &str, data: BackupData) -> ApiResult<()> {
    if data.version != BACKUP_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported backup version {} (this build restores version {BACKUP_VERSION})",
            data.version
        )));
    }
    state.store.restore(data).await?;
    audit(state, Some(actor), None, "restore", None, "ok").await;
    Ok(())
}

pub async fn create_role(state: &AppState, req: CreateRoleRequest) -> ApiResult<RoleInfo> {
    validate_role_name(&req.name)?;
    validate_permissions(&req.permissions)?;

    let now = now_unix();
    let permissions: Vec<(String, String)> = req
        .permissions
        .iter()
        .map(|perm| (perm.action.clone(), perm.path.clone()))
        .collect();

    let role = RoleRecord {
        name: req.name.clone(),
        description: req.description.clone(),
        is_admin: req.is_admin,
        permissions,
        created_at: now,
    };

    state.store.apply(Command::CreateRole { role }).await?;

    Ok(RoleInfo {
        name: req.name,
        description: req.description,
        is_admin: req.is_admin,
        permissions: req.permissions,
        created_at: rfc3339(now),
    })
}

pub async fn list_roles(state: &AppState) -> ApiResult<Vec<RoleInfo>> {
    Ok(state
        .store
        .list_roles()
        .await?
        .into_iter()
        .map(to_role_info)
        .collect())
}

pub async fn get_role(state: &AppState, name: &str) -> ApiResult<RoleInfo> {
    let role = state
        .store
        .role(name.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(to_role_info(role))
}

pub async fn set_permissions(
    state: &AppState,
    name: &str,
    permissions: Vec<PermissionRule>,
) -> ApiResult<RoleInfo> {
    validate_permissions(&permissions)?;
    let perms: Vec<(String, String)> = permissions
        .iter()
        .map(|perm| (perm.action.clone(), perm.path.clone()))
        .collect();
    state
        .store
        .apply(Command::SetPermissions {
            name: name.to_string(),
            permissions: perms,
        })
        .await?;
    get_role(state, name).await
}

pub async fn delete_role(state: &AppState, name: &str) -> ApiResult<()> {
    if name == BUILTIN_ADMIN_ROLE {
        return Err(ApiError::BadRequest(
            "the built-in 'admin' role cannot be deleted".into(),
        ));
    }
    state
        .store
        .apply(Command::DeleteRole {
            name: name.to_string(),
        })
        .await?;
    Ok(())
}

pub async fn create_token(state: &AppState, req: CreateTokenRequest) -> ApiResult<TokenCreated> {
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("token name is required".into()));
    }
    if state.store.role(req.role.clone()).await?.is_none() {
        return Err(ApiError::BadRequest(format!(
            "role '{}' does not exist",
            req.role
        )));
    }

    let token = auth::generate_token();
    let fingerprint = auth::fingerprint(&token).to_vec();
    let record = TokenRecord {
        name: req.name.clone(),
        role: Some(req.role.clone()),
        fingerprint,
        created_at: now_unix(),
        last_used_at: None,
        revoked_at: None,
    };

    state
        .store
        .apply(Command::AddToken { token: record })
        .await?;

    Ok(TokenCreated {
        name: req.name,
        role: req.role,
        token,
    })
}

pub async fn list_tokens(state: &AppState) -> ApiResult<Vec<TokenInfo>> {
    Ok(state
        .store
        .list_tokens()
        .await?
        .into_iter()
        .map(|token| TokenInfo {
            name: token.name,
            role: token.role,
            created_at: rfc3339(token.created_at),
            last_used_at: rfc3339_opt(token.last_used_at),
            revoked_at: rfc3339_opt(token.revoked_at),
        })
        .collect())
}

pub async fn revoke_token(state: &AppState, name: &str) -> ApiResult<()> {
    state
        .store
        .apply(Command::RevokeToken {
            name: name.to_string(),
            revoked_at: now_unix(),
        })
        .await?;
    Ok(())
}

fn to_role_info(role: RoleRecord) -> RoleInfo {
    RoleInfo {
        name: role.name,
        description: role.description,
        is_admin: role.is_admin,
        permissions: role
            .permissions
            .into_iter()
            .map(|(action, path)| PermissionRule { action, path })
            .collect(),
        created_at: rfc3339(role.created_at),
    }
}

fn validate_role_name(name: &str) -> ApiResult<()> {
    if name.trim().is_empty() || name.len() > 255 {
        return Err(ApiError::BadRequest(
            "role name must be between 1 and 255 characters".into(),
        ));
    }
    Ok(())
}

fn validate_permissions(permissions: &[PermissionRule]) -> ApiResult<()> {
    for perm in permissions {
        if !rbac::is_valid_action(&perm.action) {
            return Err(ApiError::BadRequest(format!(
                "invalid action '{}' (allowed: create, update, delete, rotate, *)",
                perm.action
            )));
        }
        if perm.path.is_empty() {
            return Err(ApiError::BadRequest(
                "permission path must not be empty".into(),
            ));
        }
    }
    Ok(())
}

use anyhow::anyhow;
use tokio_postgres::error::SqlState;

use hyperion_vault_core::auth;
use hyperion_vault_core::rbac;

use crate::dto::{
    CreateRoleRequest, CreateTokenRequest, PermissionRule, RoleInfo, TokenCreated, TokenInfo,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const BUILTIN_ADMIN_ROLE: &str = "admin";

pub async fn create_role(state: &AppState, req: CreateRoleRequest) -> ApiResult<RoleInfo> {
    validate_role_name(&req.name)?;
    validate_permissions(&req.permissions)?;

    let mut client = state.db.writer().await?;
    let tx = client.transaction().await?;

    let row = tx
        .query_one(
            "INSERT INTO vault.roles (name, description, is_admin) VALUES ($1, $2, $3) \
             RETURNING id::text, created_at::text",
            &[&req.name, &req.description, &req.is_admin],
        )
        .await
        .map_err(|err| unique_conflict(err, "role", &req.name))?;

    let role_id: String = row.get(0);
    let created_at: String = row.get(1);

    for perm in &req.permissions {
        tx.execute(
            "INSERT INTO vault.role_permissions (role_id, action, path_pattern) \
             VALUES ($1::uuid, $2, $3)",
            &[&role_id, &perm.action, &perm.path],
        )
        .await?;
    }

    tx.commit().await?;

    Ok(RoleInfo {
        name: req.name,
        description: req.description,
        is_admin: req.is_admin,
        permissions: req.permissions,
        created_at,
    })
}

pub async fn list_roles(state: &AppState) -> ApiResult<Vec<RoleInfo>> {
    let client = state.db.reader().await?;
    let roles = client
        .query(
            "SELECT id::text, name, description, is_admin, created_at::text \
             FROM vault.roles ORDER BY name",
            &[],
        )
        .await?;

    let mut out = Vec::with_capacity(roles.len());
    for role in roles {
        let id: String = role.get(0);
        out.push(RoleInfo {
            name: role.get(1),
            description: role.get(2),
            is_admin: role.get(3),
            permissions: load_permissions(&client, &id).await?,
            created_at: role.get(4),
        });
    }
    Ok(out)
}

pub async fn get_role(state: &AppState, name: &str) -> ApiResult<RoleInfo> {
    let client = state.db.reader().await?;
    let role = client
        .query_opt(
            "SELECT id::text, name, description, is_admin, created_at::text \
             FROM vault.roles WHERE name = $1",
            &[&name],
        )
        .await?
        .ok_or(ApiError::NotFound)?;

    let id: String = role.get(0);
    Ok(RoleInfo {
        name: role.get(1),
        description: role.get(2),
        is_admin: role.get(3),
        permissions: load_permissions(&client, &id).await?,
        created_at: role.get(4),
    })
}

pub async fn set_permissions(
    state: &AppState,
    name: &str,
    permissions: Vec<PermissionRule>,
) -> ApiResult<RoleInfo> {
    validate_permissions(&permissions)?;

    let mut client = state.db.writer().await?;
    let tx = client.transaction().await?;

    let role = tx
        .query_opt(
            "SELECT id::text FROM vault.roles WHERE name = $1 FOR UPDATE",
            &[&name],
        )
        .await?
        .ok_or(ApiError::NotFound)?;
    let role_id: String = role.get(0);

    tx.execute(
        "DELETE FROM vault.role_permissions WHERE role_id = $1::uuid",
        &[&role_id],
    )
    .await?;

    for perm in &permissions {
        tx.execute(
            "INSERT INTO vault.role_permissions (role_id, action, path_pattern) \
             VALUES ($1::uuid, $2, $3)",
            &[&role_id, &perm.action, &perm.path],
        )
        .await?;
    }

    tx.commit().await?;
    get_role(state, name).await
}

pub async fn delete_role(state: &AppState, name: &str) -> ApiResult<()> {
    if name == BUILTIN_ADMIN_ROLE {
        return Err(ApiError::BadRequest(
            "the built-in 'admin' role cannot be deleted".into(),
        ));
    }
    let client = state.db.writer().await?;
    let affected = client
        .execute("DELETE FROM vault.roles WHERE name = $1", &[&name])
        .await
        .map_err(|err| restrict_conflict(err, name))?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn create_token(state: &AppState, req: CreateTokenRequest) -> ApiResult<TokenCreated> {
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("token name is required".into()));
    }
    let client = state.db.writer().await?;

    let role = client
        .query_opt(
            "SELECT id::text FROM vault.roles WHERE name = $1",
            &[&req.role],
        )
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("role '{}' does not exist", req.role)))?;
    let role_id: String = role.get(0);

    let token = auth::generate_token();
    let fingerprint = auth::fingerprint(&token).to_vec();

    client
        .execute(
            "INSERT INTO vault.admin_tokens (name, role_id, token_sha256) \
             VALUES ($1, $2::uuid, $3)",
            &[&req.name, &role_id, &fingerprint],
        )
        .await
        .map_err(|err| unique_conflict(err, "token", &req.name))?;

    Ok(TokenCreated {
        name: req.name,
        role: req.role,
        token,
    })
}

pub async fn list_tokens(state: &AppState) -> ApiResult<Vec<TokenInfo>> {
    let client = state.db.reader().await?;
    let rows = client
        .query(
            "SELECT t.name, r.name, t.created_at::text, t.last_used_at::text, t.revoked_at::text \
             FROM vault.admin_tokens t \
             LEFT JOIN vault.roles r ON r.id = t.role_id \
             ORDER BY t.name",
            &[],
        )
        .await?;

    Ok(rows
        .iter()
        .map(|row| TokenInfo {
            name: row.get(0),
            role: row.get(1),
            created_at: row.get(2),
            last_used_at: row.get(3),
            revoked_at: row.get(4),
        })
        .collect())
}

pub async fn revoke_token(state: &AppState, name: &str) -> ApiResult<()> {
    let client = state.db.writer().await?;
    let affected = client
        .execute(
            "UPDATE vault.admin_tokens SET revoked_at = now() \
             WHERE name = $1 AND revoked_at IS NULL",
            &[&name],
        )
        .await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

async fn load_permissions(
    client: &deadpool_postgres::Client,
    role_id: &str,
) -> ApiResult<Vec<PermissionRule>> {
    let rows = client
        .query(
            "SELECT action, path_pattern FROM vault.role_permissions \
             WHERE role_id = $1::uuid ORDER BY id",
            &[&role_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| PermissionRule {
            action: row.get(0),
            path: row.get(1),
        })
        .collect())
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

fn unique_conflict(err: tokio_postgres::Error, kind: &str, name: &str) -> ApiError {
    if let Some(db_err) = err.as_db_error() {
        if db_err.code() == &SqlState::UNIQUE_VIOLATION {
            return ApiError::Conflict(format!("{kind} '{name}' already exists"));
        }
    }
    ApiError::Internal(anyhow::Error::new(err))
}

fn restrict_conflict(err: tokio_postgres::Error, name: &str) -> ApiError {
    if let Some(db_err) = err.as_db_error() {
        if db_err.code() == &SqlState::FOREIGN_KEY_VIOLATION {
            return ApiError::Conflict(format!(
                "role '{name}' still has tokens; revoke/remove them first"
            ));
        }
    }
    ApiError::Internal(anyhow!(err))
}

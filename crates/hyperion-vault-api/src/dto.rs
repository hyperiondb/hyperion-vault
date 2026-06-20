use hyperion_vault_core::{SecretFormat, SecretKind};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub kind: SecretKind,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rotation_interval_secs: Option<i64>,
    #[serde(default)]
    pub grace_period_secs: Option<i64>,
}

#[derive(Deserialize)]
pub struct UpdateSecretRequest {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rotation_interval_secs: Option<i64>,
    #[serde(default)]
    pub grace_period_secs: Option<i64>,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub value: String,
}

#[derive(Deserialize)]
pub struct BatchGetRequest {
    pub names: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SecretMetadata {
    pub name: String,
    pub kind: SecretKind,
    pub format: SecretFormat,
    pub description: Option<String>,
    pub version: i32,
    pub rotation_interval_secs: Option<i64>,
    pub grace_period_secs: i64,
    pub next_rotation_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct SecretValue {
    pub name: String,
    pub kind: SecretKind,
    pub format: SecretFormat,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub version: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PermissionRule {
    pub action: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub permissions: Vec<PermissionRule>,
}

#[derive(Deserialize)]
pub struct SetPermissionsRequest {
    pub permissions: Vec<PermissionRule>,
}

#[derive(Serialize)]
pub struct RoleInfo {
    pub name: String,
    pub description: Option<String>,
    pub is_admin: bool,
    pub permissions: Vec<PermissionRule>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct TokenCreated {
    pub name: String,
    pub role: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct TokenInfo {
    pub name: String,
    pub role: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

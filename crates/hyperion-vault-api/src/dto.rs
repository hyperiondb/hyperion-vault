use serde::{Deserialize, Serialize};
use hyperion_vault_core::SecretKind;

#[derive(Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub kind: SecretKind,
    #[serde(default)]
    pub value: Option<String>,
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

#[derive(Serialize)]
pub struct SecretMetadata {
    pub name: String,
    pub kind: SecretKind,
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
    pub version: i32,
    pub value: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub version: Option<i32>,
}

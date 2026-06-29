use serde::{Deserialize, Serialize};

use hyperion_vault_core::{SecretFormat, SecretKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub name: String,
    pub kind: SecretKind,
    pub format: SecretFormat,
    pub description: Option<String>,
    pub rotation_interval_secs: Option<i64>,
    pub grace_secs: i64,
    pub current_version: i32,
    pub next_rotation_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub target: Option<RotationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RotationTarget {
    PgReplica(PgRoleTarget),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgRoleTarget {
    pub hosts: Vec<String>,
    #[serde(default = "default_pg_database")]
    pub database: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub login_secret: Option<String>,
}

fn default_pg_database() -> String {
    "postgres".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    pub version: i32,
    pub kms_key_id: String,
    pub wrapped_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub wrapped_rotation_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRecord {
    pub name: String,
    pub description: Option<String>,
    pub is_admin: bool,
    pub permissions: Vec<(String, String)>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub name: String,
    pub role: Option<String>,
    pub fingerprint: Vec<u8>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutRecord {
    pub failures: u32,
    pub window_start: i64,
    pub locked_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: i64,
    pub actor: Option<String>,
    pub client_ip: Option<String>,
    pub action: String,
    pub secret_name: Option<String>,
    pub outcome: String,
    pub node_id: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KmsRewrapState {
    pub last_completed_rotation_at: i64,
    pub last_swept_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NextRotation {
    Keep,
    Set(Option<i64>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    CreateSecret {
        secret: SecretRecord,
        version: VersionRecord,
    },
    PutVersion {
        name: String,
        expected_current: i32,
        version: VersionRecord,
        supersede_expires_at: Option<i64>,
        set_description: Option<String>,
        set_rotation_interval_secs: Option<i64>,
        set_grace_secs: Option<i64>,
        next_rotation_at: NextRotation,
        updated_at: i64,
    },
    UpdateMeta {
        name: String,
        expected_current: i32,
        set_description: Option<String>,
        set_rotation_interval_secs: Option<i64>,
        set_grace_secs: Option<i64>,
        next_rotation_at: NextRotation,
        updated_at: i64,
    },
    DeleteSecret {
        name: String,
    },
    CreateRole {
        role: RoleRecord,
    },
    SetPermissions {
        name: String,
        permissions: Vec<(String, String)>,
    },
    DeleteRole {
        name: String,
    },
    AddToken {
        token: TokenRecord,
    },
    RevokeToken {
        name: String,
        revoked_at: i64,
    },
    TouchToken {
        fingerprint: Vec<u8>,
        at: i64,
    },
    ExpireGraceVersions {
        now: i64,
    },
    RewrapVersion {
        name: String,
        version: i32,
        kms_key_id: String,
        wrapped_dek: Vec<u8>,
        wrapped_rotation_at: i64,
    },
    SetKmsRewrapState {
        state: KmsRewrapState,
    },
    AppendAudit {
        entry: AuditEntry,
    },
    RecordAuthFailure {
        ip: String,
        now: i64,
        max: u32,
        window_secs: i64,
        lockout_secs: i64,
    },
}

impl Command {
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Command::AppendAudit { .. } | Command::RecordAuthFailure { .. }
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("write conflict; retry")]
    VersionConflict,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

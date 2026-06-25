use async_trait::async_trait;

use super::backup::BackupData;
use super::model::{
    Command, KmsRewrapState, LockoutRecord, RoleRecord, SecretRecord, StoreResult, TokenRecord,
    VersionRecord,
};

#[async_trait]
pub trait VaultReader: Send + Sync {
    async fn secret(&self, name: String) -> StoreResult<Option<SecretRecord>>;
    async fn current_version(
        &self,
        name: String,
    ) -> StoreResult<Option<(SecretRecord, VersionRecord)>>;
    async fn version(&self, name: String, version: i32) -> StoreResult<Option<VersionRecord>>;
    async fn live_versions(&self, name: String, now: i64) -> StoreResult<Vec<VersionRecord>>;
    async fn list_secrets(&self) -> StoreResult<Vec<SecretRecord>>;
    async fn due_rotations(&self, now: i64) -> StoreResult<Vec<SecretRecord>>;
    async fn role(&self, name: String) -> StoreResult<Option<RoleRecord>>;
    async fn list_roles(&self) -> StoreResult<Vec<RoleRecord>>;
    async fn token_by_fingerprint(&self, fingerprint: Vec<u8>) -> StoreResult<Option<TokenRecord>>;
    async fn list_tokens(&self) -> StoreResult<Vec<TokenRecord>>;
    async fn lockout(&self, ip: String) -> StoreResult<Option<LockoutRecord>>;
    async fn kms_rewrap_state(&self) -> StoreResult<Option<KmsRewrapState>>;
    async fn dump(&self) -> StoreResult<BackupData>;
}

#[async_trait]
pub trait VaultWriter: Send + Sync {
    async fn apply(&self, command: Command) -> StoreResult<()>;
    async fn restore(&self, data: BackupData) -> StoreResult<()>;
}

pub trait VaultStore: VaultReader + VaultWriter {}

impl<T: VaultReader + VaultWriter> VaultStore for T {}

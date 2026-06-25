use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use super::apply::apply_command;
use super::codec::{decode, encode};
use super::model::{
    Command, KmsRewrapState, LockoutRecord, RoleRecord, SecretRecord, StoreError, StoreResult,
    TokenRecord, VersionRecord,
};
use super::ports::{VaultReader, VaultWriter};

pub const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");
pub const VERSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("secret_versions");
pub const ROLES: TableDefinition<&str, &[u8]> = TableDefinition::new("roles");
pub const TOKENS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("admin_tokens");
pub const TOKENS_BY_NAME: TableDefinition<&str, &[u8]> =
    TableDefinition::new("admin_tokens_by_name");
pub const LOCKOUTS: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_lockouts");
pub const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit_log");
pub const KMS_REWRAP: TableDefinition<&str, &[u8]> = TableDefinition::new("kms_rewrap");

pub const KMS_REWRAP_STATE_KEY: &str = "state";

pub fn version_key(name: &str, version: i32) -> String {
    format!("{name}\u{0}{version:010}")
}

pub fn version_lower(name: &str) -> String {
    format!("{name}\u{0}")
}

pub fn version_upper(name: &str) -> String {
    format!("{name}\u{1}")
}

pub struct RedbStore {
    db: Arc<Database>,
    node_id: u64,
}

impl RedbStore {
    pub fn open(path: impl AsRef<Path>, node_id: u64) -> Result<Arc<Self>> {
        let db = Database::create(path)?;
        let store = Arc::new(Self {
            db: Arc::new(db),
            node_id,
        });
        store.init_tables()?;
        store.seed_admin_role()?;
        Ok(store)
    }

    pub fn database(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    fn init_tables(&self) -> Result<()> {
        let wtx = self.db.begin_write()?;
        wtx.open_table(SECRETS)?;
        wtx.open_table(VERSIONS)?;
        wtx.open_table(ROLES)?;
        wtx.open_table(TOKENS)?;
        wtx.open_table(TOKENS_BY_NAME)?;
        wtx.open_table(LOCKOUTS)?;
        wtx.open_table(AUDIT)?;
        wtx.open_table(KMS_REWRAP)?;
        wtx.commit()?;
        Ok(())
    }

    fn seed_admin_role(&self) -> Result<()> {
        {
            let rtx = self.db.begin_read()?;
            let roles = rtx.open_table(ROLES)?;
            if roles.get("admin")?.is_some() {
                return Ok(());
            }
        }
        let role = RoleRecord {
            name: "admin".to_string(),
            description: Some(
                "Full superuser access to all secrets and administration".to_string(),
            ),
            is_admin: true,
            permissions: Vec::new(),
            created_at: 0,
        };
        let wtx = self.db.begin_write()?;
        {
            let mut roles = wtx.open_table(ROLES)?;
            if roles.get("admin")?.is_none() {
                roles.insert("admin", encode(&role)?.as_slice())?;
            }
        }
        wtx.commit()?;
        Ok(())
    }
}

async fn blocking<T, F>(f: F) -> StoreResult<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result.map_err(StoreError::Internal),
        Err(join) => Err(StoreError::Internal(anyhow!(join))),
    }
}

#[async_trait]
impl VaultReader for RedbStore {
    async fn secret(&self, name: String) -> StoreResult<Option<SecretRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let table = rtx.open_table(SECRETS)?;
            match table.get(name.as_str())? {
                Some(value) => Ok(Some(decode::<SecretRecord>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn current_version(
        &self,
        name: String,
    ) -> StoreResult<Option<(SecretRecord, VersionRecord)>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let secrets = rtx.open_table(SECRETS)?;
            let secret: SecretRecord = match secrets.get(name.as_str())? {
                Some(value) => decode(value.value())?,
                None => return Ok(None),
            };
            let versions = rtx.open_table(VERSIONS)?;
            let key = version_key(&name, secret.current_version);
            match versions.get(key.as_str())? {
                Some(value) => Ok(Some((secret, decode::<VersionRecord>(value.value())?))),
                None => Ok(None),
            }
        })
        .await
    }

    async fn version(&self, name: String, version: i32) -> StoreResult<Option<VersionRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let versions = rtx.open_table(VERSIONS)?;
            let key = version_key(&name, version);
            match versions.get(key.as_str())? {
                Some(value) => Ok(Some(decode::<VersionRecord>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn live_versions(&self, name: String, now: i64) -> StoreResult<Vec<VersionRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let versions = rtx.open_table(VERSIONS)?;
            let lower = version_lower(&name);
            let upper = version_upper(&name);
            let mut out = Vec::new();
            for item in versions.range(lower.as_str()..upper.as_str())? {
                let (_key, value) = item?;
                let record: VersionRecord = decode(value.value())?;
                if record.expires_at.is_none_or(|expiry| now < expiry) {
                    out.push(record);
                }
            }
            out.sort_by_key(|record| std::cmp::Reverse(record.version));
            Ok(out)
        })
        .await
    }

    async fn list_secrets(&self) -> StoreResult<Vec<SecretRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let secrets = rtx.open_table(SECRETS)?;
            let mut out = Vec::new();
            for item in secrets.iter()? {
                let (_key, value) = item?;
                out.push(decode::<SecretRecord>(value.value())?);
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
        .await
    }

    async fn due_rotations(&self, now: i64) -> StoreResult<Vec<SecretRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let secrets = rtx.open_table(SECRETS)?;
            let mut out = Vec::new();
            for item in secrets.iter()? {
                let (_key, value) = item?;
                let record: SecretRecord = decode(value.value())?;
                if record.next_rotation_at.is_some_and(|next| next <= now) {
                    out.push(record);
                }
            }
            Ok(out)
        })
        .await
    }

    async fn role(&self, name: String) -> StoreResult<Option<RoleRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let roles = rtx.open_table(ROLES)?;
            match roles.get(name.as_str())? {
                Some(value) => Ok(Some(decode::<RoleRecord>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn list_roles(&self) -> StoreResult<Vec<RoleRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let roles = rtx.open_table(ROLES)?;
            let mut out = Vec::new();
            for item in roles.iter()? {
                let (_key, value) = item?;
                out.push(decode::<RoleRecord>(value.value())?);
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
        .await
    }

    async fn token_by_fingerprint(&self, fingerprint: Vec<u8>) -> StoreResult<Option<TokenRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let tokens = rtx.open_table(TOKENS)?;
            match tokens.get(fingerprint.as_slice())? {
                Some(value) => Ok(Some(decode::<TokenRecord>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn list_tokens(&self) -> StoreResult<Vec<TokenRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let tokens = rtx.open_table(TOKENS)?;
            let mut out = Vec::new();
            for item in tokens.iter()? {
                let (_key, value) = item?;
                out.push(decode::<TokenRecord>(value.value())?);
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
        .await
    }

    async fn lockout(&self, ip: String) -> StoreResult<Option<LockoutRecord>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let locks = rtx.open_table(LOCKOUTS)?;
            match locks.get(ip.as_str())? {
                Some(value) => Ok(Some(decode::<LockoutRecord>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn kms_rewrap_state(&self) -> StoreResult<Option<KmsRewrapState>> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read()?;
            let table = rtx.open_table(KMS_REWRAP)?;
            match table.get(KMS_REWRAP_STATE_KEY)? {
                Some(value) => Ok(Some(decode::<KmsRewrapState>(value.value())?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn dump(&self) -> StoreResult<super::backup::BackupData> {
        let db = self.db.clone();
        blocking(move || super::backup::dump_database(&db)).await
    }
}

#[async_trait]
impl VaultWriter for RedbStore {
    async fn apply(&self, command: Command) -> StoreResult<()> {
        let db = self.db.clone();
        let node_id = self.node_id;
        let join = tokio::task::spawn_blocking(move || -> StoreResult<()> {
            let wtx = db
                .begin_write()
                .map_err(|e| StoreError::Internal(anyhow!(e)))?;
            apply_command(&wtx, node_id, &command)?;
            wtx.commit().map_err(|e| StoreError::Internal(anyhow!(e)))?;
            Ok(())
        })
        .await;
        match join {
            Ok(result) => result,
            Err(join_err) => Err(StoreError::Internal(anyhow!(join_err))),
        }
    }

    async fn restore(&self, data: super::backup::BackupData) -> StoreResult<()> {
        let db = self.db.clone();
        blocking(move || super::backup::restore_database(&db, &data)).await
    }
}

use anyhow::{bail, Context, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::engine::{AUDIT, KMS_REWRAP, ROLES, SECRETS, TOKENS, TOKENS_BY_NAME, VERSIONS};

pub const BACKUP_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupData {
    pub version: u32,
    pub secrets: Vec<(String, Vec<u8>)>,
    pub versions: Vec<(String, Vec<u8>)>,
    pub roles: Vec<(String, Vec<u8>)>,
    pub tokens: Vec<(Vec<u8>, Vec<u8>)>,
    pub tokens_by_name: Vec<(String, Vec<u8>)>,
    pub audit: Vec<(u64, Vec<u8>)>,
    #[serde(default)]
    pub kms_rewrap: Vec<(String, Vec<u8>)>,
}

pub fn dump_database(db: &Database) -> Result<BackupData> {
    let rtx = db.begin_read().context("open read txn for backup")?;
    let data = BackupData {
        version: BACKUP_VERSION,
        secrets: dump_str(&rtx, SECRETS)?,
        versions: dump_str(&rtx, VERSIONS)?,
        roles: dump_str(&rtx, ROLES)?,
        tokens: dump_bytes(&rtx, TOKENS)?,
        tokens_by_name: dump_str(&rtx, TOKENS_BY_NAME)?,
        audit: dump_u64(&rtx, AUDIT)?,
        kms_rewrap: dump_str(&rtx, KMS_REWRAP)?,
    };
    drop(rtx);
    Ok(data)
}

pub fn restore_database(db: &Database, data: &BackupData) -> Result<()> {
    if data.version != BACKUP_VERSION {
        bail!(
            "unsupported backup version {} (this build restores version {BACKUP_VERSION})",
            data.version
        );
    }
    let wtx = db.begin_write().context("open write txn for restore")?;
    {
        restore_str(&wtx, SECRETS, &data.secrets)?;
        restore_str(&wtx, VERSIONS, &data.versions)?;
        restore_str(&wtx, ROLES, &data.roles)?;
        restore_str(&wtx, TOKENS_BY_NAME, &data.tokens_by_name)?;
        restore_bytes(&wtx, TOKENS, &data.tokens)?;
        restore_u64(&wtx, AUDIT, &data.audit)?;
        restore_str(&wtx, KMS_REWRAP, &data.kms_rewrap)?;
    }
    wtx.commit().context("commit restore")?;
    Ok(())
}

fn dump_str(
    rtx: &redb::ReadTransaction,
    def: TableDefinition<&'static str, &'static [u8]>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let table = rtx.open_table(def)?;
    let mut out = Vec::new();
    for item in table.iter()? {
        let (key, value) = item?;
        out.push((key.value().to_string(), value.value().to_vec()));
    }
    Ok(out)
}

fn dump_bytes(
    rtx: &redb::ReadTransaction,
    def: TableDefinition<&'static [u8], &'static [u8]>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let table = rtx.open_table(def)?;
    let mut out = Vec::new();
    for item in table.iter()? {
        let (key, value) = item?;
        out.push((key.value().to_vec(), value.value().to_vec()));
    }
    Ok(out)
}

fn dump_u64(
    rtx: &redb::ReadTransaction,
    def: TableDefinition<u64, &'static [u8]>,
) -> Result<Vec<(u64, Vec<u8>)>> {
    let table = rtx.open_table(def)?;
    let mut out = Vec::new();
    for item in table.iter()? {
        let (key, value) = item?;
        out.push((key.value(), value.value().to_vec()));
    }
    Ok(out)
}

fn restore_str(
    wtx: &redb::WriteTransaction,
    def: TableDefinition<&'static str, &'static [u8]>,
    rows: &[(String, Vec<u8>)],
) -> Result<()> {
    let mut table = wtx.open_table(def)?;
    let keys: Vec<String> = table
        .iter()?
        .filter_map(|item| item.ok().map(|(key, _)| key.value().to_string()))
        .collect();
    for key in keys {
        table.remove(key.as_str())?;
    }
    for (key, value) in rows {
        table.insert(key.as_str(), value.as_slice())?;
    }
    Ok(())
}

fn restore_bytes(
    wtx: &redb::WriteTransaction,
    def: TableDefinition<&'static [u8], &'static [u8]>,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    let mut table = wtx.open_table(def)?;
    let keys: Vec<Vec<u8>> = table
        .iter()?
        .filter_map(|item| item.ok().map(|(key, _)| key.value().to_vec()))
        .collect();
    for key in keys {
        table.remove(key.as_slice())?;
    }
    for (key, value) in rows {
        table.insert(key.as_slice(), value.as_slice())?;
    }
    Ok(())
}

fn restore_u64(
    wtx: &redb::WriteTransaction,
    def: TableDefinition<u64, &'static [u8]>,
    rows: &[(u64, Vec<u8>)],
) -> Result<()> {
    let mut table = wtx.open_table(def)?;
    let keys: Vec<u64> = table
        .iter()?
        .filter_map(|item| item.ok().map(|(key, _)| key.value()))
        .collect();
    for key in keys {
        table.remove(key)?;
    }
    for (key, value) in rows {
        table.insert(*key, value.as_slice())?;
    }
    Ok(())
}

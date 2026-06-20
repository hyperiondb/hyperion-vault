use std::collections::BTreeMap;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine};
use openraft::storage::{RaftSnapshotBuilder, Snapshot};
use openraft::{
    AnyError, Entry, EntryPayload, LogId, OptionalSend, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership, Vote,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::types::{ApplyResult, NodeId, TypeConfig};
use crate::store::apply::apply_command;
use crate::store::engine::{RedbStore, ROLES, SECRETS, TOKENS, TOKENS_BY_NAME, VERSIONS};

const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");

const META_VOTE: &str = "vote";
const META_PURGED: &str = "last_purged";
const META_APPLIED: &str = "last_applied";
const META_MEMBERSHIP: &str = "membership";
const META_SNAPSHOT: &str = "snapshot";

fn read_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<NodeId> {
    StorageIOError::read(AnyError::new(&e)).into()
}

fn write_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<NodeId> {
    StorageIOError::write(AnyError::new(&e)).into()
}

fn read_meta<T: for<'de> Deserialize<'de>>(
    db: &Database,
    key: &str,
) -> Result<Option<T>, StorageError<NodeId>> {
    let rtx = db.begin_read().map_err(read_err)?;
    let table = rtx.open_table(META).map_err(read_err)?;
    match table.get(key).map_err(read_err)? {
        Some(value) => Ok(Some(
            serde_json::from_slice(value.value()).map_err(read_err)?,
        )),
        None => Ok(None),
    }
}

fn write_meta<T: Serialize>(
    db: &Database,
    key: &str,
    value: &T,
) -> Result<(), StorageError<NodeId>> {
    let bytes = serde_json::to_vec(value).map_err(write_err)?;
    let wtx = db.begin_write().map_err(write_err)?;
    {
        let mut table = wtx.open_table(META).map_err(write_err)?;
        table.insert(key, bytes.as_slice()).map_err(write_err)?;
    }
    wtx.commit().map_err(write_err)?;
    Ok(())
}

#[derive(Clone)]
pub struct LogStore {
    db: Arc<Database>,
}

impl LogStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl openraft::RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let rtx = self.db.begin_read().map_err(read_err)?;
        let table = rtx.open_table(LOG).map_err(read_err)?;
        let mut out = Vec::new();
        for item in table.range(range).map_err(read_err)? {
            let (_index, value) = item.map_err(read_err)?;
            out.push(serde_json::from_slice(value.value()).map_err(read_err)?);
        }
        Ok(out)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> = read_meta(&self.db, META_PURGED)?;
        let rtx = self.db.begin_read().map_err(read_err)?;
        let table = rtx.open_table(LOG).map_err(read_err)?;
        let last = match table.last().map_err(read_err)? {
            Some((_index, value)) => {
                let entry: Entry<TypeConfig> =
                    serde_json::from_slice(value.value()).map_err(read_err)?;
                Some(entry.log_id)
            }
            None => last_purged,
        };
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        write_meta(&self.db, META_VOTE, vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        read_meta(&self.db, META_VOTE)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let wtx = self.db.begin_write().map_err(write_err)?;
            {
                let mut table = wtx.open_table(LOG).map_err(write_err)?;
                for entry in entries {
                    let bytes = serde_json::to_vec(&entry).map_err(write_err)?;
                    table
                        .insert(entry.log_id.index, bytes.as_slice())
                        .map_err(write_err)?;
                }
            }
            wtx.commit().map_err(write_err)?;
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let wtx = self.db.begin_write().map_err(write_err)?;
        {
            let mut table = wtx.open_table(LOG).map_err(write_err)?;
            let keys: Vec<u64> = table
                .range(log_id.index..)
                .map_err(write_err)?
                .filter_map(|item| item.ok().map(|(index, _)| index.value()))
                .collect();
            for key in keys {
                table.remove(key).map_err(write_err)?;
            }
        }
        wtx.commit().map_err(write_err)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        {
            let wtx = self.db.begin_write().map_err(write_err)?;
            {
                let mut table = wtx.open_table(LOG).map_err(write_err)?;
                let keys: Vec<u64> = table
                    .range(..=log_id.index)
                    .map_err(write_err)?
                    .filter_map(|item| item.ok().map(|(index, _)| index.value()))
                    .collect();
                for key in keys {
                    table.remove(key).map_err(write_err)?;
                }
            }
            wtx.commit().map_err(write_err)?;
        }
        write_meta(&self.db, META_PURGED, &log_id)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct SnapshotData {
    secrets: Vec<(String, Vec<u8>)>,
    versions: Vec<(String, Vec<u8>)>,
    roles: Vec<(String, Vec<u8>)>,
    tokens: Vec<(Vec<u8>, Vec<u8>)>,
    tokens_by_name: Vec<(String, Vec<u8>)>,
    last_applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, openraft::BasicNode>,
}

#[derive(Clone)]
pub struct StateMachine {
    store: Arc<RedbStore>,
}

impl StateMachine {
    pub fn new(store: Arc<RedbStore>) -> Self {
        Self { store }
    }

    fn db(&self) -> Arc<Database> {
        self.store.database()
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let db = self.db();
        let last_applied: Option<LogId<NodeId>> = read_meta(&db, META_APPLIED)?;
        let membership: StoredMembership<NodeId, openraft::BasicNode> =
            read_meta(&db, META_MEMBERSHIP)?.unwrap_or_default();

        let rtx = db.begin_read().map_err(read_err)?;

        let tokens = {
            let table = rtx.open_table(TOKENS).map_err(read_err)?;
            let mut out = Vec::new();
            for item in table.iter().map_err(read_err)? {
                let (key, value) = item.map_err(read_err)?;
                out.push((key.value().to_vec(), value.value().to_vec()));
            }
            out
        };

        let data = SnapshotData {
            secrets: dump_str_table(&rtx, SECRETS)?,
            versions: dump_str_table(&rtx, VERSIONS)?,
            roles: dump_str_table(&rtx, ROLES)?,
            tokens,
            tokens_by_name: dump_str_table(&rtx, TOKENS_BY_NAME)?,
            last_applied,
            membership: membership.clone(),
        };
        drop(rtx);

        let bytes = serde_json::to_vec(&data).map_err(write_err)?;
        let snapshot_id = match last_applied {
            Some(log_id) => format!("{}-{}", log_id.leader_id, log_id.index),
            None => "empty".to_string(),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership: membership,
            snapshot_id,
        };
        write_meta(&db, META_SNAPSHOT, &bytes)?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, openraft::BasicNode>,
        ),
        StorageError<NodeId>,
    > {
        let db = self.db();
        let last_applied = read_meta(&db, META_APPLIED)?;
        let membership = read_meta(&db, META_MEMBERSHIP)?.unwrap_or_default();
        Ok((last_applied, membership))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ApplyResult>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let db = self.db();
        let node_id = self.store.node_id();
        let mut results = Vec::new();

        let wtx = db.begin_write().map_err(write_err)?;
        let mut last_applied: Option<LogId<NodeId>> = None;
        let mut membership: Option<StoredMembership<NodeId, openraft::BasicNode>> = None;

        for entry in entries {
            last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => results.push(ApplyResult {
                    ok: true,
                    error: None,
                }),
                EntryPayload::Normal(command) => match apply_command(&wtx, node_id, &command) {
                    Ok(()) => results.push(ApplyResult {
                        ok: true,
                        error: None,
                    }),
                    Err(crate::store::StoreError::Internal(err)) => {
                        let io = std::io::Error::other(err.to_string());
                        return Err(StorageIOError::write(AnyError::new(&io)).into());
                    }
                    Err(err) => results.push(ApplyResult {
                        ok: false,
                        error: Some(err.to_string()),
                    }),
                },
                EntryPayload::Membership(member) => {
                    membership = Some(StoredMembership::new(Some(entry.log_id), member));
                    results.push(ApplyResult {
                        ok: true,
                        error: None,
                    });
                }
            }
        }

        if let Some(log_id) = last_applied {
            let bytes = serde_json::to_vec(&log_id).map_err(write_err)?;
            let mut table = wtx.open_table(META).map_err(write_err)?;
            table
                .insert(META_APPLIED, bytes.as_slice())
                .map_err(write_err)?;
            if let Some(member) = &membership {
                let mbytes = serde_json::to_vec(member).map_err(write_err)?;
                table
                    .insert(META_MEMBERSHIP, mbytes.as_slice())
                    .map_err(write_err)?;
            }
        }
        wtx.commit().map_err(write_err)?;

        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, openraft::BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data: SnapshotData =
            serde_json::from_slice(snapshot.get_ref().as_slice()).map_err(read_err)?;
        let db = self.db();
        let wtx = db.begin_write().map_err(write_err)?;
        {
            restore_str_table(&wtx, SECRETS, &data.secrets)?;
            restore_str_table(&wtx, VERSIONS, &data.versions)?;
            restore_str_table(&wtx, ROLES, &data.roles)?;
            restore_str_table(&wtx, TOKENS_BY_NAME, &data.tokens_by_name)?;
            let mut table = wtx.open_table(TOKENS).map_err(write_err)?;
            clear_bytes_table(&mut table)?;
            for (key, value) in &data.tokens {
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(write_err)?;
            }
        }
        {
            let mut table = wtx.open_table(META).map_err(write_err)?;
            let lbytes = serde_json::to_vec(&meta.last_log_id).map_err(write_err)?;
            table
                .insert(META_APPLIED, lbytes.as_slice())
                .map_err(write_err)?;
            let mbytes = serde_json::to_vec(&meta.last_membership).map_err(write_err)?;
            table
                .insert(META_MEMBERSHIP, mbytes.as_slice())
                .map_err(write_err)?;
        }
        wtx.commit().map_err(write_err)?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let db = self.db();
        let bytes: Option<Vec<u8>> = read_meta(&db, META_SNAPSHOT)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let last_applied: Option<LogId<NodeId>> = read_meta(&db, META_APPLIED)?;
        let membership: StoredMembership<NodeId, openraft::BasicNode> =
            read_meta(&db, META_MEMBERSHIP)?.unwrap_or_default();
        let snapshot_id = match last_applied {
            Some(log_id) => format!("{}-{}", log_id.leader_id, log_id.index),
            None => "empty".to_string(),
        };
        Ok(Some(Snapshot {
            meta: SnapshotMeta {
                last_log_id: last_applied,
                last_membership: membership,
                snapshot_id,
            },
            snapshot: Box::new(Cursor::new(bytes)),
        }))
    }
}

fn dump_str_table(
    rtx: &redb::ReadTransaction,
    def: TableDefinition<&'static str, &'static [u8]>,
) -> Result<Vec<(String, Vec<u8>)>, StorageError<NodeId>> {
    let table = rtx.open_table(def).map_err(read_err)?;
    let mut out = Vec::new();
    for item in table.iter().map_err(read_err)? {
        let (key, value) = item.map_err(read_err)?;
        out.push((key.value().to_string(), value.value().to_vec()));
    }
    Ok(out)
}

fn restore_str_table(
    wtx: &redb::WriteTransaction,
    def: TableDefinition<&'static str, &'static [u8]>,
    rows: &[(String, Vec<u8>)],
) -> Result<(), StorageError<NodeId>> {
    let mut table = wtx.open_table(def).map_err(write_err)?;
    let keys: Vec<String> = table
        .iter()
        .map_err(write_err)?
        .filter_map(|item| item.ok().map(|(key, _)| key.value().to_string()))
        .collect();
    for key in keys {
        table.remove(key.as_str()).map_err(write_err)?;
    }
    for (key, value) in rows {
        table
            .insert(key.as_str(), value.as_slice())
            .map_err(write_err)?;
    }
    Ok(())
}

fn clear_bytes_table(
    table: &mut redb::Table<&'static [u8], &'static [u8]>,
) -> Result<(), StorageError<NodeId>> {
    let keys: Vec<Vec<u8>> = table
        .iter()
        .map_err(write_err)?
        .filter_map(|item| item.ok().map(|(key, _)| key.value().to_vec()))
        .collect();
    for key in keys {
        table.remove(key.as_slice()).map_err(write_err)?;
    }
    Ok(())
}

pub fn membership_default() -> BTreeMap<NodeId, openraft::BasicNode> {
    BTreeMap::new()
}

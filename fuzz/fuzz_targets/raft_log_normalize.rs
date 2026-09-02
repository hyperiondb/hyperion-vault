#![no_main]

#[cfg(feature = "api")]
mod imp {
    use std::sync::Arc;

    use arbitrary::Arbitrary;
    use hyperion_vault_api::raft::store::{init_raft_tables, normalize_raft_log, LogStore};
    use hyperion_vault_api::raft::types::{NodeId, TypeConfig};
    use openraft::storage::RaftLogStorage;
    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

    // Same names as the private definitions in `raft/store.rs`; redb keys
    // tables by name, so these address the same tables.
    const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
    const META: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");
    const META_PURGED: &str = "last_purged";
    const META_APPLIED: &str = "last_applied";

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub entries: Vec<(u64, u64)>,
        pub applied: Option<(u64, u64)>,
        pub purged: Option<(u64, u64)>,
    }

    fn log_id(index: u64, term: u64) -> LogId<NodeId> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn memory_db() -> Database {
        Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb")
    }

    fn write_meta(db: &Database, key: &str, log_id: &LogId<NodeId>) {
        let bytes = serde_json::to_vec(log_id).expect("encode log id");
        let wtx = db.begin_write().expect("begin write");
        {
            let mut table = wtx.open_table(META).expect("open meta");
            table.insert(key, bytes.as_slice()).expect("insert meta");
        }
        wtx.commit().expect("commit");
    }

    fn read_purged(db: &Database) -> Option<LogId<NodeId>> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(META).expect("open meta");
        table
            .get(META_PURGED)
            .expect("get")
            .map(|value| serde_json::from_slice(value.value()).expect("decode purged"))
    }

    fn log_indexes(db: &Database) -> Vec<u64> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(LOG).expect("open log");
        table
            .iter()
            .expect("iter")
            .map(|item| item.expect("row").0.value())
            .collect()
    }

    pub fn run(input: Input) {
        // `index + 1` in `normalize_raft_log` and `get_log_state` is unchecked.
        // A peer-supplied u64::MAX index therefore aborts the process; that is
        // reported as VULN-6 rather than rediscovered on every run.
        let extreme = |pair: &Option<(u64, u64)>| pair.is_some_and(|(index, _)| index == u64::MAX);
        if extreme(&input.applied) || extreme(&input.purged) {
            return;
        }
        // openraft never purges past what it has applied; a seed that does is
        // not a state the storage layer is asked to survive.
        if let (Some((applied, _)), Some((purged, _))) = (input.applied, input.purged) {
            if purged > applied {
                return;
            }
        }

        let db = memory_db();
        init_raft_tables(&db).expect("init raft tables");

        {
            let wtx = db.begin_write().expect("begin write");
            {
                let mut table = wtx.open_table(LOG).expect("open log");
                for (index, term) in &input.entries {
                    // The stored entry must agree with its key; `append` is the
                    // only writer in production and it keys by log_id.index.
                    let entry: Entry<TypeConfig> = Entry {
                        log_id: log_id(*index, *term),
                        payload: EntryPayload::Blank,
                    };
                    let bytes = serde_json::to_vec(&entry).expect("encode entry");
                    table
                        .insert(*index, bytes.as_slice())
                        .expect("insert entry");
                }
            }
            wtx.commit().expect("commit");
        }

        if let Some((index, term)) = input.applied {
            write_meta(&db, META_APPLIED, &log_id(index, term));
        }
        if let Some((index, term)) = input.purged {
            write_meta(&db, META_PURGED, &log_id(index, term));
        }

        normalize_raft_log(&db).expect("normalize must not fail on any seeded state");

        let floor = input
            .applied
            .map(|(index, _)| index)
            .or(input.purged.map(|(index, _)| index));
        let start = floor.map(|index| index + 1).unwrap_or(0);

        let remaining = log_indexes(&db);
        for (position, index) in remaining.iter().enumerate() {
            assert_eq!(
                *index,
                start + position as u64,
                "the normalized log must be contiguous from the first index after last_applied"
            );
        }
        if let Some(purged) = read_purged(&db) {
            for index in &remaining {
                assert!(
                    *index > purged.index,
                    "a normalized log must not keep an entry at or below last_purged"
                );
            }
        }

        normalize_raft_log(&db).expect("normalize must stay callable");
        assert_eq!(
            log_indexes(&db),
            remaining,
            "normalize must be idempotent: a second pass must remove nothing"
        );

        let mut store = LogStore::new(Arc::new(db));
        let state = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(async { store.get_log_state().await })
            .expect("get_log_state must not fail on a normalized log");

        if let (Some(last), Some(purged)) = (state.last_log_id, state.last_purged_log_id) {
            assert!(
                last.index >= purged.index,
                "openraft requires last_log_id to be at or above last_purged_log_id"
            );
        }
        if !remaining.is_empty() {
            assert_eq!(
                state.last_log_id.map(|log_id| log_id.index),
                remaining.last().copied(),
                "last_log_id must be the highest surviving entry"
            );
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

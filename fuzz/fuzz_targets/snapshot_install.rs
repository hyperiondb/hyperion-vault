#![no_main]

#[cfg(feature = "api")]
mod imp {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Arc;

    use arbitrary::Arbitrary;
    use hyperion_vault_api::raft::store::{init_raft_tables, StateMachine};
    use hyperion_vault_api::raft::types::NodeId;
    use hyperion_vault_api::store::engine::{
        split_version_key, RedbStore, KMS_REWRAP, ROLES, SECRETS, TOKENS, TOKENS_BY_NAME, VERSIONS,
    };
    use hyperion_vault_core::{is_valid_secret_name, is_valid_secret_version};
    use openraft::storage::RaftStateMachine;
    use openraft::{
        BasicNode, CommittedLeaderId, LogId, Membership, SnapshotMeta, StoredMembership,
    };
    use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

    const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub existing_secrets: Vec<(String, Vec<u8>)>,
        pub existing_log: Vec<u32>,
        pub secrets: Vec<(String, Vec<u8>)>,
        pub versions: Vec<(String, Vec<u8>)>,
        pub roles: Vec<(String, Vec<u8>)>,
        pub tokens: Vec<(Vec<u8>, Vec<u8>)>,
        pub tokens_by_name: Vec<(String, Vec<u8>)>,
        pub kms_rewrap: Vec<(String, Vec<u8>)>,
        // Always present, never None; the None case has its own unit test in
        // raft::store, and keeping it Some here keeps the log-truncation
        // assertion below meaningful.
        pub last_log_id: (u32, u64),
        pub raw_instead: Option<Vec<u8>>,
    }

    fn log_id(index: u64, term: u64) -> LogId<NodeId> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn membership() -> StoredMembership<NodeId, BasicNode> {
        let mut nodes = BTreeMap::new();
        nodes.insert(1u64, BasicNode::new("vault1:7400"));
        nodes.insert(2u64, BasicNode::new("vault2:7400"));
        let voters = nodes.keys().copied().collect();
        StoredMembership::new(None, Membership::new(vec![voters], nodes))
    }

    fn memory_db() -> Database {
        Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb")
    }

    fn dump_str(
        db: &Database,
        def: TableDefinition<&'static str, &'static [u8]>,
    ) -> Vec<(String, Vec<u8>)> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(def).expect("open table");
        table
            .iter()
            .expect("iter")
            .map(|item| {
                let (key, value) = item.expect("row");
                (key.value().to_string(), value.value().to_vec())
            })
            .collect()
    }

    fn dump_tokens(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(TOKENS).expect("open tokens");
        table
            .iter()
            .expect("iter")
            .map(|item| {
                let (key, value) = item.expect("row");
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect()
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

    // install_snapshot refuses any row the ordinary write paths would refuse.
    fn rows_are_acceptable(input: &Input) -> bool {
        input
            .secrets
            .iter()
            .all(|(name, _)| is_valid_secret_name(name))
            && input.versions.iter().all(|(key, _)| {
                split_version_key(key).is_some_and(|(name, version)| {
                    is_valid_secret_name(name) && is_valid_secret_version(version)
                })
            })
    }

    // redb keeps one row per key and orders by key.
    fn collapse<K: Ord + Clone, V: Clone>(rows: &[(K, V)]) -> Vec<(K, V)> {
        rows.iter()
            .cloned()
            .collect::<BTreeMap<K, V>>()
            .into_iter()
            .collect()
    }

    // A snapshot arrives from a peer over `POST /raft/snapshot`. Rows the write
    // paths would refuse are rejected whole; every other snapshot must install
    // and must leave the store in exactly the snapshot's state.
    pub fn run(input: Input) {
        let db = Arc::new(memory_db());
        init_raft_tables(&db).expect("init raft tables");
        let store = RedbStore::from_database(db.clone(), 1).expect("build store");

        {
            let wtx = db.begin_write().expect("begin write");
            {
                let mut secrets = wtx.open_table(SECRETS).expect("open secrets");
                for (key, value) in &input.existing_secrets {
                    secrets
                        .insert(key.as_str(), value.as_slice())
                        .expect("insert existing secret");
                }
            }
            {
                let mut log = wtx.open_table(LOG).expect("open log");
                for index in &input.existing_log {
                    log.insert(u64::from(*index), b"entry".as_slice())
                        .expect("insert existing log entry");
                }
            }
            wtx.commit().expect("commit");
        }

        let (index, term) = input.last_log_id;
        let last_log_id = Some(log_id(u64::from(index), term));
        let meta = SnapshotMeta::<NodeId, BasicNode> {
            last_log_id,
            last_membership: membership(),
            snapshot_id: "fuzz".to_string(),
        };

        let well_formed = serde_json::json!({
            "secrets": input.secrets,
            "versions": input.versions,
            "roles": input.roles,
            "tokens": input.tokens,
            "tokens_by_name": input.tokens_by_name,
            "kms_rewrap": input.kms_rewrap,
            "last_applied": last_log_id,
            "membership": membership(),
        });
        let raw = match &input.raw_instead {
            Some(bytes) => bytes.clone(),
            None => serde_json::to_vec(&well_formed).expect("encode snapshot data"),
        };

        let mut machine = StateMachine::new(store);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");

        let installed = runtime.block_on(async {
            machine
                .install_snapshot(&meta, Box::new(Cursor::new(raw)))
                .await
        });

        if installed.is_err() {
            assert!(
                input.raw_instead.is_some() || !rows_are_acceptable(&input),
                "a snapshot carrying only acceptable rows must install"
            );
            return;
        }

        let (applied, stored_membership) = runtime
            .block_on(async { machine.applied_state().await })
            .expect("applied_state after install");
        assert_eq!(
            applied, meta.last_log_id,
            "install_snapshot must record the snapshot's last_log_id as applied"
        );
        assert_eq!(
            stored_membership, meta.last_membership,
            "install_snapshot must record the snapshot's membership"
        );

        if input.raw_instead.is_some() {
            // Arbitrary bytes that happened to parse: the row assertions below
            // are about the rows this target chose, so stop here.
            return;
        }

        assert_eq!(
            dump_str(&db, SECRETS),
            collapse(&input.secrets),
            "install_snapshot must replace the secrets table with exactly the snapshot's rows"
        );
        assert_eq!(
            dump_str(&db, VERSIONS),
            collapse(&input.versions),
            "install_snapshot must replace the versions table"
        );
        assert_eq!(
            dump_str(&db, ROLES),
            collapse(&input.roles),
            "install_snapshot must replace the roles table"
        );
        assert_eq!(
            dump_str(&db, TOKENS_BY_NAME),
            collapse(&input.tokens_by_name),
            "install_snapshot must replace the token index"
        );
        assert_eq!(
            dump_str(&db, KMS_REWRAP),
            collapse(&input.kms_rewrap),
            "install_snapshot must replace the kms rewrap table"
        );
        assert_eq!(
            dump_tokens(&db),
            collapse(&input.tokens),
            "install_snapshot must replace the tokens table"
        );

        if let Some(last) = meta.last_log_id {
            for index in log_indexes(&db) {
                assert!(
                    index > last.index,
                    "a log entry covered by the installed snapshot must be removed"
                );
            }
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

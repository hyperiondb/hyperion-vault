#![no_main]

#[cfg(feature = "api")]
mod imp {
    use std::collections::BTreeMap;

    use arbitrary::Arbitrary;
    use hyperion_vault_api::store::backup::{
        dump_database, restore_database, BackupData, BACKUP_VERSION,
    };
    use hyperion_vault_api::store::engine::{
        split_version_key, AUDIT, KMS_REWRAP, MAX_AUDIT_KEY, ROLES, SECRETS, TOKENS,
        TOKENS_BY_NAME, VERSIONS,
    };
    use hyperion_vault_core::{is_valid_secret_name, is_valid_secret_version};
    use redb::Database;

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub version: u32,
        pub secrets: Vec<(String, Vec<u8>)>,
        pub versions: Vec<(String, Vec<u8>)>,
        pub roles: Vec<(String, Vec<u8>)>,
        pub tokens: Vec<(Vec<u8>, Vec<u8>)>,
        pub tokens_by_name: Vec<(String, Vec<u8>)>,
        pub audit: Vec<(u64, Vec<u8>)>,
        pub kms_rewrap: Vec<(String, Vec<u8>)>,
    }

    fn memory_db() -> Database {
        Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb")
    }

    fn init(db: &Database) {
        let wtx = db.begin_write().expect("begin write");
        wtx.open_table(SECRETS).expect("secrets");
        wtx.open_table(VERSIONS).expect("versions");
        wtx.open_table(ROLES).expect("roles");
        wtx.open_table(TOKENS).expect("tokens");
        wtx.open_table(TOKENS_BY_NAME).expect("tokens_by_name");
        wtx.open_table(AUDIT).expect("audit");
        wtx.open_table(KMS_REWRAP).expect("kms_rewrap");
        wtx.commit().expect("commit");
    }

    fn to_backup(input: &Input) -> BackupData {
        BackupData {
            version: input.version,
            secrets: input.secrets.clone(),
            versions: input.versions.clone(),
            roles: input.roles.clone(),
            tokens: input.tokens.clone(),
            tokens_by_name: input.tokens_by_name.clone(),
            audit: input.audit.clone(),
            kms_rewrap: input.kms_rewrap.clone(),
        }
    }

    // redb keeps one row per key and orders by key, so a duplicate key in the
    // backup file collapses to its last occurrence.
    fn collapse<K: Ord + Clone, V: Clone>(rows: &[(K, V)]) -> Vec<(K, V)> {
        let map: BTreeMap<K, V> = rows.iter().cloned().collect();
        map.into_iter().collect()
    }

    fn expected(input: &Input) -> BackupData {
        BackupData {
            version: BACKUP_VERSION,
            secrets: collapse(&input.secrets),
            versions: collapse(&input.versions),
            roles: collapse(&input.roles),
            tokens: collapse(&input.tokens),
            tokens_by_name: collapse(&input.tokens_by_name),
            audit: collapse(&input.audit),
            kms_rewrap: collapse(&input.kms_rewrap),
        }
    }

    fn same(a: &BackupData, b: &BackupData) -> bool {
        a.version == b.version
            && a.secrets == b.secrets
            && a.versions == b.versions
            && a.roles == b.roles
            && a.tokens == b.tokens
            && a.tokens_by_name == b.tokens_by_name
            && a.audit == b.audit
            && a.kms_rewrap == b.kms_rewrap
    }

    // Every row a restore writes must be one the write paths would accept, so a
    // backup carrying a name outside the character set, a version key that does
    // not belong to a secret in it, or an audit key above the plausible range is
    // refused. An accepted restore must be exactly reversible.
    fn rows_are_acceptable(data: &BackupData) -> bool {
        data.secrets
            .iter()
            .all(|(name, _)| is_valid_secret_name(name))
            && data.versions.iter().all(|(key, _)| {
                split_version_key(key).is_some_and(|(name, version)| {
                    is_valid_secret_name(name) && is_valid_secret_version(version)
                })
            })
            && data.audit.iter().all(|(key, _)| *key <= MAX_AUDIT_KEY)
    }

    pub fn run(input: Input) {
        let db = memory_db();
        init(&db);
        let data = to_backup(&input);

        if input.version != BACKUP_VERSION || !rows_are_acceptable(&data) {
            let before = dump_database(&db).expect("dump before rejected restore");
            assert!(
                restore_database(&db, &data).is_err(),
                "a foreign backup version or an unacceptable row must be rejected"
            );
            let after = dump_database(&db).expect("dump after rejected restore");
            assert!(
                same(&before, &after),
                "a rejected restore must leave the store untouched"
            );
            return;
        }

        restore_database(&db, &data).expect("restore of a well-versioned backup");
        let dumped = dump_database(&db).expect("dump after restore");
        assert!(
            same(&dumped, &expected(&input)),
            "dump after restore must reproduce the restored rows exactly"
        );

        restore_database(&db, &data).expect("second restore");
        let again = dump_database(&db).expect("dump after second restore");
        assert!(same(&dumped, &again), "restore must be idempotent");

        // A dump must itself be restorable without drift.
        restore_database(&db, &dumped).expect("restore of a dump");
        let round = dump_database(&db).expect("dump after restoring a dump");
        assert!(
            same(&dumped, &round),
            "dump -> restore -> dump must be stable"
        );
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

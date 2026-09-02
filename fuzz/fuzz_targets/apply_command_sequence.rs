#![no_main]

#[cfg(feature = "api")]
mod imp {
    use arbitrary::Arbitrary;
    use hyperion_vault_api::store::apply::apply_command;
    use hyperion_vault_api::store::codec::decode;
    use hyperion_vault_api::store::engine::{
        version_key, version_lower, version_upper, AUDIT, KMS_REWRAP, LOCKOUTS, ROLES, SECRETS,
        TOKENS, TOKENS_BY_NAME, VERSIONS,
    };
    use hyperion_vault_api::store::{
        AuditEntry, Command, KmsRewrapState, LockoutRecord, NextRotation, RoleRecord, SecretRecord,
        StoreError, StoreResult, TokenRecord, VersionRecord,
    };
    use hyperion_vault_core::{SecretFormat, SecretKind};
    use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

    const NODE_ID: u64 = 7;

    #[derive(Arbitrary, Debug)]
    pub enum Name {
        Pool(u8),
        Raw(String),
    }

    impl Name {
        // A small pool makes conflicts, deletes and re-reads actually collide;
        // raw names keep the wilder inputs. The two version-key separator bytes
        // are stripped on purpose — the `store_key_encoding` target already
        // covers what a name containing them does to the key ranges.
        fn get(&self) -> String {
            match self {
                Name::Pool(index) => format!("s{}", index % 6),
                Name::Raw(raw) => raw.replace(['\u{0}', '\u{1}'], "_"),
            }
        }
    }

    #[derive(Arbitrary, Debug)]
    pub struct SecretInput {
        pub automatic: bool,
        pub userpass: bool,
        pub description: Option<String>,
        pub rotation_interval_secs: Option<i32>,
        pub grace_secs: i32,
        pub current_version: i32,
        pub next_rotation_at: Option<i32>,
        pub created_at: i32,
    }

    #[derive(Arbitrary, Debug)]
    pub struct VersionInput {
        pub version: i32,
        pub kms_key_id: String,
        pub wrapped_dek: Vec<u8>,
        pub nonce: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub aad: Vec<u8>,
        pub created_at: i32,
        pub expires_at: Option<i32>,
        pub wrapped_rotation_at: Option<i32>,
    }

    #[derive(Arbitrary, Debug)]
    pub enum Op {
        CreateSecret {
            name: Name,
            secret: SecretInput,
            version: VersionInput,
        },
        PutVersion {
            name: Name,
            expected_current: i32,
            version: VersionInput,
            supersede_expires_at: Option<i32>,
            set_description: Option<String>,
            set_rotation_interval_secs: Option<i32>,
            set_grace_secs: Option<i32>,
            set_next_rotation: Option<Option<i32>>,
            updated_at: i32,
        },
        UpdateMeta {
            name: Name,
            expected_current: i32,
            set_description: Option<String>,
            set_rotation_interval_secs: Option<i32>,
            set_grace_secs: Option<i32>,
            set_next_rotation: Option<Option<i32>>,
            updated_at: i32,
        },
        DeleteSecret {
            name: Name,
        },
        CreateRole {
            name: Name,
            description: Option<String>,
            is_admin: bool,
            permissions: Vec<(String, String)>,
            created_at: i32,
        },
        SetPermissions {
            name: Name,
            permissions: Vec<(String, String)>,
        },
        DeleteRole {
            name: Name,
        },
        AddToken {
            name: Name,
            role: Option<Name>,
            fingerprint: Vec<u8>,
            created_at: i32,
        },
        RevokeToken {
            name: Name,
            revoked_at: i32,
        },
        TouchToken {
            fingerprint: Vec<u8>,
            at: i32,
        },
        ExpireGraceVersions {
            now: i32,
        },
        RewrapVersion {
            name: Name,
            version: i32,
            kms_key_id: String,
            wrapped_dek: Vec<u8>,
            wrapped_rotation_at: i32,
        },
        SetKmsRewrapState {
            last_completed_rotation_at: i32,
            last_swept_at: i32,
            updated_at: i32,
        },
        AppendAudit {
            at: i32,
            actor: Option<String>,
            client_ip: Option<String>,
            action: String,
            secret_name: Option<Name>,
            outcome: String,
        },
        // The lockout fields are deliberately narrower than the wire types.
        // `RecordAuthFailure` does unchecked i64 arithmetic on them (VULN.md,
        // VULN-5); bounding them here keeps this target on the state-machine
        // properties instead of rediscovering that one overflow every run.
        RecordAuthFailure {
            ip: String,
            now: i32,
            max: u8,
            window_secs: u16,
            lockout_secs: u16,
        },
    }

    fn version_record(input: &VersionInput) -> VersionRecord {
        VersionRecord {
            version: input.version,
            kms_key_id: input.kms_key_id.clone(),
            wrapped_dek: input.wrapped_dek.clone(),
            nonce: input.nonce.clone(),
            ciphertext: input.ciphertext.clone(),
            aad: input.aad.clone(),
            created_at: i64::from(input.created_at),
            expires_at: input.expires_at.map(i64::from),
            wrapped_rotation_at: input.wrapped_rotation_at.map(i64::from),
        }
    }

    fn next_rotation(value: &Option<Option<i32>>) -> NextRotation {
        match value {
            None => NextRotation::Keep,
            Some(inner) => NextRotation::Set(inner.map(i64::from)),
        }
    }

    fn to_command(op: &Op) -> Command {
        match op {
            Op::CreateSecret {
                name,
                secret,
                version,
            } => Command::CreateSecret {
                secret: SecretRecord {
                    name: name.get(),
                    kind: if secret.automatic {
                        SecretKind::Automatic
                    } else {
                        SecretKind::Manual
                    },
                    format: if secret.userpass {
                        SecretFormat::Userpass
                    } else {
                        SecretFormat::Opaque
                    },
                    description: secret.description.clone(),
                    rotation_interval_secs: secret.rotation_interval_secs.map(i64::from),
                    grace_secs: i64::from(secret.grace_secs),
                    current_version: secret.current_version,
                    next_rotation_at: secret.next_rotation_at.map(i64::from),
                    created_at: i64::from(secret.created_at),
                    updated_at: i64::from(secret.created_at),
                    target: None,
                },
                version: version_record(version),
            },
            Op::PutVersion {
                name,
                expected_current,
                version,
                supersede_expires_at,
                set_description,
                set_rotation_interval_secs,
                set_grace_secs,
                set_next_rotation,
                updated_at,
            } => Command::PutVersion {
                name: name.get(),
                expected_current: *expected_current,
                version: version_record(version),
                supersede_expires_at: supersede_expires_at.map(i64::from),
                set_description: set_description.clone(),
                set_rotation_interval_secs: set_rotation_interval_secs.map(i64::from),
                set_grace_secs: set_grace_secs.map(i64::from),
                next_rotation_at: next_rotation(set_next_rotation),
                updated_at: i64::from(*updated_at),
            },
            Op::UpdateMeta {
                name,
                expected_current,
                set_description,
                set_rotation_interval_secs,
                set_grace_secs,
                set_next_rotation,
                updated_at,
            } => Command::UpdateMeta {
                name: name.get(),
                expected_current: *expected_current,
                set_description: set_description.clone(),
                set_rotation_interval_secs: set_rotation_interval_secs.map(i64::from),
                set_grace_secs: set_grace_secs.map(i64::from),
                next_rotation_at: next_rotation(set_next_rotation),
                updated_at: i64::from(*updated_at),
            },
            Op::DeleteSecret { name } => Command::DeleteSecret { name: name.get() },
            Op::CreateRole {
                name,
                description,
                is_admin,
                permissions,
                created_at,
            } => Command::CreateRole {
                role: RoleRecord {
                    name: name.get(),
                    description: description.clone(),
                    is_admin: *is_admin,
                    permissions: permissions.clone(),
                    created_at: i64::from(*created_at),
                },
            },
            Op::SetPermissions { name, permissions } => Command::SetPermissions {
                name: name.get(),
                permissions: permissions.clone(),
            },
            Op::DeleteRole { name } => Command::DeleteRole { name: name.get() },
            Op::AddToken {
                name,
                role,
                fingerprint,
                created_at,
            } => Command::AddToken {
                token: TokenRecord {
                    name: name.get(),
                    role: role.as_ref().map(|role| role.get()),
                    fingerprint: fingerprint.clone(),
                    created_at: i64::from(*created_at),
                    last_used_at: None,
                    revoked_at: None,
                },
            },
            Op::RevokeToken { name, revoked_at } => Command::RevokeToken {
                name: name.get(),
                revoked_at: i64::from(*revoked_at),
            },
            Op::TouchToken { fingerprint, at } => Command::TouchToken {
                fingerprint: fingerprint.clone(),
                at: i64::from(*at),
            },
            Op::ExpireGraceVersions { now } => Command::ExpireGraceVersions {
                now: i64::from(*now),
            },
            Op::RewrapVersion {
                name,
                version,
                kms_key_id,
                wrapped_dek,
                wrapped_rotation_at,
            } => Command::RewrapVersion {
                name: name.get(),
                version: *version,
                kms_key_id: kms_key_id.clone(),
                wrapped_dek: wrapped_dek.clone(),
                wrapped_rotation_at: i64::from(*wrapped_rotation_at),
            },
            Op::SetKmsRewrapState {
                last_completed_rotation_at,
                last_swept_at,
                updated_at,
            } => Command::SetKmsRewrapState {
                state: KmsRewrapState {
                    last_completed_rotation_at: i64::from(*last_completed_rotation_at),
                    last_swept_at: i64::from(*last_swept_at),
                    updated_at: i64::from(*updated_at),
                },
            },
            Op::AppendAudit {
                at,
                actor,
                client_ip,
                action,
                secret_name,
                outcome,
            } => Command::AppendAudit {
                entry: AuditEntry {
                    at: i64::from(*at),
                    actor: actor.clone(),
                    client_ip: client_ip.clone(),
                    action: action.clone(),
                    secret_name: secret_name.as_ref().map(|name| name.get()),
                    outcome: outcome.clone(),
                    node_id: 0,
                },
            },
            Op::RecordAuthFailure {
                ip,
                now,
                max,
                window_secs,
                lockout_secs,
            } => Command::RecordAuthFailure {
                ip: ip.clone(),
                now: i64::from(*now),
                max: u32::from(*max),
                window_secs: i64::from(*window_secs),
                lockout_secs: i64::from(*lockout_secs),
            },
        }
    }

    fn memory_db() -> Database {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .expect("in-memory redb");
        let wtx = db.begin_write().expect("begin write");
        wtx.open_table(SECRETS).expect("secrets");
        wtx.open_table(VERSIONS).expect("versions");
        wtx.open_table(ROLES).expect("roles");
        wtx.open_table(TOKENS).expect("tokens");
        wtx.open_table(TOKENS_BY_NAME).expect("tokens_by_name");
        wtx.open_table(LOCKOUTS).expect("lockouts");
        wtx.open_table(AUDIT).expect("audit");
        wtx.open_table(KMS_REWRAP).expect("kms_rewrap");
        wtx.commit().expect("commit");
        db
    }

    // Mirrors `RedbStore::apply`: a failed command aborts its transaction, so a
    // rejected write must leave no trace.
    fn apply_one(db: &Database, command: &Command) -> StoreResult<()> {
        let wtx = db.begin_write().expect("begin write");
        match apply_command(&wtx, NODE_ID, command) {
            Ok(()) => {
                wtx.commit().expect("commit");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn result_code(result: &StoreResult<()>) -> u8 {
        match result {
            Ok(()) => 0,
            Err(StoreError::NotFound) => 1,
            Err(StoreError::Conflict(_)) => 2,
            Err(StoreError::VersionConflict) => 3,
            Err(StoreError::Internal(_)) => 4,
        }
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

    fn dump_bytes(
        db: &Database,
        def: TableDefinition<&'static [u8], &'static [u8]>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(def).expect("open table");
        table
            .iter()
            .expect("iter")
            .map(|item| {
                let (key, value) = item.expect("row");
                (key.value().to_vec(), value.value().to_vec())
            })
            .collect()
    }

    fn dump_u64(db: &Database, def: TableDefinition<u64, &'static [u8]>) -> Vec<(u64, Vec<u8>)> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(def).expect("open table");
        table
            .iter()
            .expect("iter")
            .map(|item| {
                let (key, value) = item.expect("row");
                (key.value(), value.value().to_vec())
            })
            .collect()
    }

    #[derive(PartialEq, Eq)]
    struct Snapshot {
        secrets: Vec<(String, Vec<u8>)>,
        versions: Vec<(String, Vec<u8>)>,
        roles: Vec<(String, Vec<u8>)>,
        tokens_by_name: Vec<(String, Vec<u8>)>,
        lockouts: Vec<(String, Vec<u8>)>,
        kms_rewrap: Vec<(String, Vec<u8>)>,
        tokens: Vec<(Vec<u8>, Vec<u8>)>,
        audit: Vec<(u64, Vec<u8>)>,
    }

    fn snapshot(db: &Database) -> Snapshot {
        Snapshot {
            secrets: dump_str(db, SECRETS),
            versions: dump_str(db, VERSIONS),
            roles: dump_str(db, ROLES),
            tokens_by_name: dump_str(db, TOKENS_BY_NAME),
            lockouts: dump_str(db, LOCKOUTS),
            kms_rewrap: dump_str(db, KMS_REWRAP),
            tokens: dump_bytes(db, TOKENS),
            audit: dump_u64(db, AUDIT),
        }
    }

    fn version_keys(db: &Database, name: &str) -> Vec<String> {
        let lower = version_lower(name);
        let upper = version_upper(name);
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(VERSIONS).expect("open versions");
        table
            .range(lower.as_str()..upper.as_str())
            .expect("range")
            .map(|item| item.expect("row").0.value().to_string())
            .collect()
    }

    fn read_version_row(db: &Database, key: &str) -> Option<Vec<u8>> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(VERSIONS).expect("open versions");
        table
            .get(key)
            .expect("get")
            .map(|value| value.value().to_vec())
    }

    // The rows this command's checks need to see before it runs. Snapshotting
    // every table before every command would be quadratic.
    enum Before {
        Secret(String, Option<Vec<u8>>),
        Versions(Vec<(String, Vec<u8>)>),
        Version(String, Option<Vec<u8>>),
        Nothing,
    }

    fn snapshot_before(db: &Database, command: &Command) -> Before {
        match command {
            Command::CreateSecret { secret, .. } => {
                let rtx = db.begin_read().expect("begin read");
                let table = rtx.open_table(SECRETS).expect("open secrets");
                let row = table
                    .get(secret.name.as_str())
                    .expect("get")
                    .map(|value| value.value().to_vec());
                Before::Secret(secret.name.clone(), row)
            }
            Command::DeleteSecret { .. } => Before::Versions(dump_str(db, VERSIONS)),
            Command::RewrapVersion { name, version, .. } => {
                let key = version_key(name, *version);
                let row = read_version_row(db, key.as_str());
                Before::Version(key, row)
            }
            _ => Before::Nothing,
        }
    }

    fn check_per_command(
        db: &Database,
        command: &Command,
        before: &Before,
        result: &StoreResult<()>,
    ) {
        match (command, before) {
            (Command::CreateSecret { .. }, Before::Secret(name, row)) => {
                if row.is_some() {
                    assert!(
                        matches!(result, Err(StoreError::Conflict(_))),
                        "a second CreateSecret for the same name must be a conflict"
                    );
                    let rtx = db.begin_read().expect("begin read");
                    let table = rtx.open_table(SECRETS).expect("open secrets");
                    let now = table
                        .get(name.as_str())
                        .expect("get")
                        .map(|value| value.value().to_vec());
                    assert_eq!(
                        &now, row,
                        "a rejected CreateSecret must not overwrite the stored secret"
                    );
                }
            }
            (Command::DeleteSecret { name }, Before::Versions(rows)) => {
                if result.is_err() {
                    return;
                }
                assert!(
                    version_keys(db, name).is_empty(),
                    "a successful DeleteSecret must clear its own version range"
                );
                let after: Vec<String> = dump_str(db, VERSIONS)
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect();
                let prefix = version_lower(name);
                for (key, _) in rows {
                    if after.contains(key) {
                        continue;
                    }
                    let field = key.strip_prefix(prefix.as_str()).unwrap_or_else(|| {
                        panic!("DeleteSecret removed a row outside its own key prefix: {key:?}")
                    });
                    let version: i32 = field.parse().unwrap_or_else(|_| {
                        panic!("DeleteSecret removed a row with a foreign version field: {key:?}")
                    });
                    assert_eq!(
                        &version_key(name, version),
                        key,
                        "DeleteSecret removed a row that is not one of its own versions"
                    );
                }
            }
            (Command::RewrapVersion { .. }, Before::Version(key, Some(bytes))) => {
                let old: VersionRecord = decode(bytes).expect("decode stored version");
                let now = read_version_row(db, key.as_str())
                    .expect("RewrapVersion must not remove the row");
                let new: VersionRecord = decode(&now).expect("decode rewrapped version");
                assert_eq!(
                    old.ciphertext, new.ciphertext,
                    "rewrap must not touch the ciphertext"
                );
                assert_eq!(old.nonce, new.nonce, "rewrap must not touch the nonce");
                assert_eq!(old.aad, new.aad, "rewrap must not touch the aad");
                assert_eq!(
                    old.version, new.version,
                    "rewrap must not renumber a version"
                );
            }
            _ => {}
        }
    }

    fn check_end_state(db: &Database) {
        let state = snapshot(db);

        for (key, bytes) in &state.secrets {
            let record: SecretRecord = decode(bytes).expect("stored secret must decode");
            assert_eq!(&record.name, key, "a secret row must be keyed by its name");
        }
        for (key, bytes) in &state.roles {
            let record: RoleRecord = decode(bytes).expect("stored role must decode");
            assert_eq!(&record.name, key, "a role row must be keyed by its name");
        }
        for (key, bytes) in &state.tokens {
            let record: TokenRecord = decode(bytes).expect("stored token must decode");
            assert_eq!(
                &record.fingerprint, key,
                "a token row must be keyed by its own fingerprint"
            );
        }
        for (_name, fingerprint) in &state.tokens_by_name {
            assert!(
                state.tokens.iter().any(|(key, _)| key == fingerprint),
                "every name in the token index must resolve to a token row"
            );
        }
        for (_ip, bytes) in &state.lockouts {
            let record: LockoutRecord = decode(bytes).expect("stored lockout must decode");
            assert!(
                record.failures >= 1,
                "a lockout row is only written on a failure"
            );
        }
        for (position, (key, _)) in state.audit.iter().enumerate() {
            assert_eq!(
                *key, position as u64,
                "the audit log must stay a gap-free sequence from zero"
            );
        }
        for (key, _) in &state.versions {
            let separator = key
                .find('\u{0}')
                .expect("a version key must carry the name/version separator");
            let (name, field) = key.split_at(separator);
            let version: i32 = field[1..]
                .parse()
                .expect("a version key must end in a parseable version");
            assert_eq!(
                &version_key(name, version),
                key,
                "a version key must re-encode to itself"
            );
        }
    }

    // The redb state machine is the Raft apply path: it must be deterministic
    // (two replicas applying the same log must reach byte-identical state) and
    // it must keep the per-table invariants the read path assumes.
    pub fn run(ops: Vec<Op>) {
        let commands: Vec<Command> = ops.iter().map(to_command).collect();

        let primary = memory_db();
        let replica = memory_db();

        let mut primary_codes = Vec::with_capacity(commands.len());
        let mut replica_codes = Vec::with_capacity(commands.len());

        for command in &commands {
            let before = snapshot_before(&primary, command);
            let result = apply_one(&primary, command);
            primary_codes.push(result_code(&result));
            check_per_command(&primary, command, &before, &result);
        }
        for command in &commands {
            replica_codes.push(result_code(&apply_one(&replica, command)));
        }

        assert_eq!(
            primary_codes, replica_codes,
            "the same command sequence must produce the same outcomes on every replica"
        );
        assert!(
            snapshot(&primary) == snapshot(&replica),
            "the same command sequence must produce byte-identical state on every replica"
        );

        check_end_state(&primary);
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|ops: Vec<imp::Op>| imp::run(ops));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

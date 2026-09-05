use anyhow::anyhow;
use redb::{ReadableTable, WriteTransaction};

use super::codec::{decode, encode};
use super::engine::{
    version_from_key, version_key, version_lower, version_upper, AUDIT, KMS_REWRAP,
    KMS_REWRAP_STATE_KEY, LOCKOUTS, MAX_AUDIT_KEY, ROLES, SECRETS, TOKENS, TOKENS_BY_NAME,
    VERSIONS,
};
use super::model::{
    Command, LockoutRecord, NextRotation, SecretRecord, StoreError, StoreResult, TokenRecord,
    VersionRecord,
};

fn err<E: std::fmt::Debug>(e: E) -> StoreError {
    StoreError::Internal(anyhow!("redb: {e:?}"))
}

pub fn check_secret_row(name: &str, version: i32) -> StoreResult<()> {
    check_secret_name(name)?;
    if !hyperion_vault_core::is_valid_secret_version(version) {
        return Err(StoreError::Conflict(format!(
            "secret version {version} is below the minimum of {}",
            hyperion_vault_core::MIN_SECRET_VERSION
        )));
    }
    Ok(())
}

pub fn check_secret_name(name: &str) -> StoreResult<()> {
    if hyperion_vault_core::is_valid_secret_name(name) {
        Ok(())
    } else {
        Err(StoreError::Conflict(format!(
            "secret name {name:?} is outside [A-Za-z0-9-_/.] or longer than {} bytes",
            hyperion_vault_core::MAX_SECRET_NAME_LEN
        )))
    }
}

pub fn apply_command(wtx: &WriteTransaction, node_id: u64, command: &Command) -> StoreResult<()> {
    match command {
        Command::CreateSecret { secret, version } => {
            check_secret_row(&secret.name, version.version)?;
            {
                let mut secrets = wtx.open_table(SECRETS).map_err(err)?;
                if secrets.get(secret.name.as_str()).map_err(err)?.is_some() {
                    return Err(StoreError::Conflict(format!(
                        "secret '{}' already exists",
                        secret.name
                    )));
                }
                secrets
                    .insert(secret.name.as_str(), encode(secret)?.as_slice())
                    .map_err(err)?;
            }
            let mut versions = wtx.open_table(VERSIONS).map_err(err)?;
            versions
                .insert(
                    version_key(&secret.name, version.version).as_str(),
                    encode(version)?.as_slice(),
                )
                .map_err(err)?;
            Ok(())
        }

        Command::PutVersion {
            name,
            expected_current,
            version,
            supersede_expires_at,
            set_description,
            set_rotation_interval_secs,
            set_grace_secs,
            next_rotation_at,
            updated_at,
        } => {
            check_secret_row(name, version.version)?;
            let mut secrets = wtx.open_table(SECRETS).map_err(err)?;
            let mut secret: SecretRecord = match secrets.get(name.as_str()).map_err(err)? {
                Some(value) => decode(value.value())?,
                None => return Err(StoreError::NotFound),
            };
            if secret.current_version != *expected_current {
                return Err(StoreError::VersionConflict);
            }
            {
                let mut versions = wtx.open_table(VERSIONS).map_err(err)?;
                versions
                    .insert(
                        version_key(name, version.version).as_str(),
                        encode(version)?.as_slice(),
                    )
                    .map_err(err)?;
                if let Some(expiry) = supersede_expires_at {
                    let prev_key = version_key(name, *expected_current);
                    let prev: Option<VersionRecord> =
                        match versions.get(prev_key.as_str()).map_err(err)? {
                            Some(value) => Some(decode(value.value())?),
                            None => None,
                        };
                    if let Some(mut prev) = prev {
                        if prev.expires_at.is_none() {
                            prev.expires_at = Some(*expiry);
                            versions
                                .insert(prev_key.as_str(), encode(&prev)?.as_slice())
                                .map_err(err)?;
                        }
                    }
                }
            }
            secret.current_version = version.version;
            apply_meta(
                &mut secret,
                set_description,
                set_rotation_interval_secs,
                set_grace_secs,
                next_rotation_at,
                *updated_at,
            );
            secrets
                .insert(name.as_str(), encode(&secret)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::UpdateMeta {
            name,
            expected_current,
            set_description,
            set_rotation_interval_secs,
            set_grace_secs,
            next_rotation_at,
            updated_at,
        } => {
            let mut secrets = wtx.open_table(SECRETS).map_err(err)?;
            let mut secret: SecretRecord = match secrets.get(name.as_str()).map_err(err)? {
                Some(value) => decode(value.value())?,
                None => return Err(StoreError::NotFound),
            };
            if secret.current_version != *expected_current {
                return Err(StoreError::VersionConflict);
            }
            apply_meta(
                &mut secret,
                set_description,
                set_rotation_interval_secs,
                set_grace_secs,
                next_rotation_at,
                *updated_at,
            );
            secrets
                .insert(name.as_str(), encode(&secret)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::DeleteSecret { name } => {
            {
                let mut secrets = wtx.open_table(SECRETS).map_err(err)?;
                if secrets.remove(name.as_str()).map_err(err)?.is_none() {
                    return Err(StoreError::NotFound);
                }
            }
            let mut versions = wtx.open_table(VERSIONS).map_err(err)?;
            let keys: Vec<String> = {
                let lower = version_lower(name);
                let upper = version_upper(name);
                let mut keys = Vec::new();
                for item in versions
                    .range(lower.as_str()..upper.as_str())
                    .map_err(err)?
                {
                    let (key, _value) = item.map_err(err)?;
                    let key = key.value();
                    if version_from_key(name, key).is_none() {
                        continue;
                    }
                    keys.push(key.to_string());
                }
                keys
            };
            for key in keys {
                versions.remove(key.as_str()).map_err(err)?;
            }
            Ok(())
        }

        Command::CreateRole { role } => {
            let mut roles = wtx.open_table(ROLES).map_err(err)?;
            if roles.get(role.name.as_str()).map_err(err)?.is_some() {
                return Err(StoreError::Conflict(format!(
                    "role '{}' already exists",
                    role.name
                )));
            }
            roles
                .insert(role.name.as_str(), encode(role)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::SetPermissions { name, permissions } => {
            let mut roles = wtx.open_table(ROLES).map_err(err)?;
            let mut role = match roles.get(name.as_str()).map_err(err)? {
                Some(value) => decode::<super::model::RoleRecord>(value.value())?,
                None => return Err(StoreError::NotFound),
            };
            role.permissions = permissions.clone();
            roles
                .insert(name.as_str(), encode(&role)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::DeleteRole { name } => {
            {
                let tokens = wtx.open_table(TOKENS).map_err(err)?;
                for item in tokens.iter().map_err(err)? {
                    let (_key, value) = item.map_err(err)?;
                    let token: TokenRecord = decode(value.value())?;
                    if token.role.as_deref() == Some(name.as_str()) {
                        return Err(StoreError::Conflict(format!(
                            "role '{name}' still has tokens; revoke/remove them first"
                        )));
                    }
                }
            }
            let mut roles = wtx.open_table(ROLES).map_err(err)?;
            if roles.remove(name.as_str()).map_err(err)?.is_none() {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        Command::AddToken { token } => {
            {
                let tokens = wtx.open_table(TOKENS).map_err(err)?;
                if tokens
                    .get(token.fingerprint.as_slice())
                    .map_err(err)?
                    .is_some()
                {
                    return Err(StoreError::Conflict(
                        "a token with this fingerprint already exists".to_string(),
                    ));
                }
            }
            {
                let mut by_name = wtx.open_table(TOKENS_BY_NAME).map_err(err)?;
                if by_name.get(token.name.as_str()).map_err(err)?.is_some() {
                    return Err(StoreError::Conflict(format!(
                        "token '{}' already exists",
                        token.name
                    )));
                }
                by_name
                    .insert(token.name.as_str(), token.fingerprint.as_slice())
                    .map_err(err)?;
            }
            let mut tokens = wtx.open_table(TOKENS).map_err(err)?;
            tokens
                .insert(token.fingerprint.as_slice(), encode(token)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::RevokeToken { name, revoked_at } => {
            let fingerprint: Vec<u8> = {
                let by_name = wtx.open_table(TOKENS_BY_NAME).map_err(err)?;
                let found = by_name.get(name.as_str()).map_err(err)?;
                match found {
                    Some(value) => value.value().to_vec(),
                    None => return Err(StoreError::NotFound),
                }
            };
            let mut tokens = wtx.open_table(TOKENS).map_err(err)?;
            let mut token: TokenRecord = match tokens.get(fingerprint.as_slice()).map_err(err)? {
                Some(value) => decode(value.value())?,
                None => return Err(StoreError::NotFound),
            };
            if token.revoked_at.is_some() {
                return Err(StoreError::NotFound);
            }
            token.revoked_at = Some(*revoked_at);
            tokens
                .insert(fingerprint.as_slice(), encode(&token)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::TouchToken { fingerprint, at } => {
            let mut tokens = wtx.open_table(TOKENS).map_err(err)?;
            let existing: Option<TokenRecord> =
                match tokens.get(fingerprint.as_slice()).map_err(err)? {
                    Some(value) => Some(decode(value.value())?),
                    None => None,
                };
            if let Some(mut token) = existing {
                token.last_used_at = Some(*at);
                tokens
                    .insert(fingerprint.as_slice(), encode(&token)?.as_slice())
                    .map_err(err)?;
            }
            Ok(())
        }

        Command::ExpireGraceVersions { now } => {
            let mut versions = wtx.open_table(VERSIONS).map_err(err)?;
            let expired: Vec<String> = {
                let mut keys = Vec::new();
                for item in versions.iter().map_err(err)? {
                    let (key, value) = item.map_err(err)?;
                    let record: VersionRecord = decode(value.value())?;
                    if record.expires_at.is_some_and(|expiry| expiry <= *now) {
                        keys.push(key.value().to_string());
                    }
                }
                keys
            };
            for key in expired {
                versions.remove(key.as_str()).map_err(err)?;
            }
            Ok(())
        }

        Command::RewrapVersion {
            name,
            version,
            kms_key_id,
            wrapped_dek,
            wrapped_rotation_at,
        } => {
            let mut versions = wtx.open_table(VERSIONS).map_err(err)?;
            let key = version_key(name, *version);
            let mut record: VersionRecord = match versions.get(key.as_str()).map_err(err)? {
                Some(value) => decode(value.value())?,
                None => return Ok(()),
            };
            if record
                .wrapped_rotation_at
                .is_some_and(|current| current >= *wrapped_rotation_at)
            {
                return Ok(());
            }
            record.kms_key_id = kms_key_id.clone();
            record.wrapped_dek = wrapped_dek.clone();
            record.wrapped_rotation_at = Some(*wrapped_rotation_at);
            versions
                .insert(key.as_str(), encode(&record)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::SetKmsRewrapState { state } => {
            let mut table = wtx.open_table(KMS_REWRAP).map_err(err)?;
            table
                .insert(KMS_REWRAP_STATE_KEY, encode(state)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::AppendAudit { entry } => {
            let mut audit = wtx.open_table(AUDIT).map_err(err)?;
            // A row above the plausible range can only come from a tampered
            // backup or snapshot; ignore it so appends keep working.
            let last: Option<u64> = {
                let mut range = audit.range(..=MAX_AUDIT_KEY).map_err(err)?;
                match range.next_back() {
                    Some(item) => Some(item.map_err(err)?.0.value()),
                    None => None,
                }
            };
            let next: u64 = match last {
                Some(key) => key.checked_add(1).ok_or_else(|| {
                    StoreError::Conflict("audit log key space is exhausted".to_string())
                })?,
                None => 0,
            };
            let mut entry = entry.clone();
            entry.node_id = node_id;
            audit
                .insert(next, encode(&entry)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        // A restore replaces every table, so it is replicated like any other
        // write and every node applies the same rows at the same log index.
        Command::RestoreDatabase { data } => super::backup::restore_tables(wtx, data)
            .map_err(|err| StoreError::Conflict(format!("restore refused: {err}"))),

        Command::RecordAuthFailure {
            key,
            now,
            max,
            window_secs,
            lockout_secs,
        } => {
            let mut locks = wtx.open_table(LOCKOUTS).map_err(err)?;
            let mut record: LockoutRecord = match locks.get(key.as_str()).map_err(err)? {
                Some(value) => decode(value.value())?,
                None => LockoutRecord {
                    failures: 0,
                    window_start: *now,
                    locked_until: None,
                },
            };
            if *now - record.window_start >= *window_secs {
                record.failures = 0;
                record.window_start = *now;
            }
            record.failures += 1;
            if record.failures >= *max {
                record.locked_until = Some(*now + *lockout_secs);
            }
            locks
                .insert(key.as_str(), encode(&record)?.as_slice())
                .map_err(err)?;
            Ok(())
        }
    }
}

fn apply_meta(
    secret: &mut SecretRecord,
    set_description: &Option<String>,
    set_rotation_interval_secs: &Option<i64>,
    set_grace_secs: &Option<i64>,
    next_rotation_at: &NextRotation,
    updated_at: i64,
) {
    if let Some(description) = set_description {
        secret.description = Some(description.clone());
    }
    if let Some(interval) = set_rotation_interval_secs {
        secret.rotation_interval_secs = Some(*interval);
    }
    if let Some(grace) = set_grace_secs {
        secret.grace_secs = *grace;
    }
    if let NextRotation::Set(value) = next_rotation_at {
        secret.next_rotation_at = *value;
    }
    secret.updated_at = updated_at;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::engine::version_key;
    use crate::store::model::KmsRewrapState;
    use hyperion_vault_core::{SecretFormat, SecretKind};
    use redb::{Database, ReadableDatabase};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tmp_db() -> Database {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("hv-apply-test-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&path);
        Database::create(path).expect("create db")
    }

    fn apply(db: &Database, command: Command) -> StoreResult<()> {
        let wtx = db.begin_write().expect("begin write");
        let result = apply_command(&wtx, 1, &command);
        wtx.commit().expect("commit");
        result
    }

    fn read_version(db: &Database, name: &str, version: i32) -> VersionRecord {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(VERSIONS).expect("open versions");
        let key = version_key(name, version);
        let value = table
            .get(key.as_str())
            .expect("get")
            .expect("version present");
        decode(value.value()).expect("decode version")
    }

    fn sample() -> (SecretRecord, VersionRecord) {
        let secret = SecretRecord {
            name: "db/password".to_string(),
            kind: SecretKind::Manual,
            format: SecretFormat::Opaque,
            description: None,
            rotation_interval_secs: None,
            grace_secs: 0,
            current_version: 1,
            next_rotation_at: None,
            created_at: 0,
            updated_at: 0,
            target: None,
        };
        let version = VersionRecord {
            version: 1,
            kms_key_id: "old-key".to_string(),
            wrapped_dek: vec![1, 2, 3],
            nonce: vec![4; 24],
            ciphertext: vec![9, 9, 9],
            aad: b"db/password:1".to_vec(),
            created_at: 0,
            expires_at: None,
            wrapped_rotation_at: None,
        };
        (secret, version)
    }

    fn insert_raw_version(db: &Database, key: &str, record: &VersionRecord) {
        let wtx = db.begin_write().expect("begin write");
        {
            let mut table = wtx.open_table(VERSIONS).expect("open versions");
            table
                .insert(key, encode(record).expect("encode").as_slice())
                .expect("insert");
        }
        wtx.commit().expect("commit");
    }

    fn version_keys(db: &Database) -> Vec<String> {
        let rtx = db.begin_read().expect("begin read");
        // A refused command commits nothing, so on a fresh database the table
        // has never been created and "no table" means "no rows".
        let table = match rtx.open_table(VERSIONS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Vec::new(),
            Err(err) => panic!("open versions: {err}"),
        };
        table
            .iter()
            .expect("iter")
            .filter_map(|item| item.ok().map(|(key, _)| key.value().to_string()))
            .collect()
    }

    fn audit_keys(db: &Database) -> Vec<u64> {
        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(AUDIT).expect("open audit");
        table
            .iter()
            .expect("iter")
            .filter_map(|item| item.ok().map(|(key, _)| key.value()))
            .collect()
    }

    fn audit_entry(action: &str) -> super::super::model::AuditEntry {
        super::super::model::AuditEntry {
            at: 0,
            actor: None,
            client_ip: None,
            action: action.to_string(),
            secret_name: None,
            outcome: "ok".to_string(),
            node_id: 0,
        }
    }

    fn sample_token(name: &str, fingerprint: Vec<u8>) -> TokenRecord {
        TokenRecord {
            name: name.to_string(),
            role: Some("admin".to_string()),
            fingerprint,
            created_at: 0,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn a_replicated_restore_replaces_every_table() {
        let db = tmp_db();
        let (secret, version) = sample();
        apply(&db, Command::CreateSecret { secret, version }).expect("create");

        let backup = super::super::backup::BackupData {
            version: super::super::backup::BACKUP_VERSION,
            secrets: vec![("other/secret".to_string(), vec![1, 2, 3])],
            versions: vec![(version_key("other/secret", 1), vec![4, 5, 6])],
            ..Default::default()
        };
        apply(
            &db,
            Command::RestoreDatabase {
                data: Box::new(backup),
            },
        )
        .expect("restore");

        assert_eq!(
            version_keys(&db),
            vec![version_key("other/secret", 1)],
            "a restore replaces the rows that were there"
        );
    }

    #[test]
    fn a_replicated_restore_with_an_invalid_row_is_refused() {
        let db = tmp_db();
        let (secret, version) = sample();
        apply(&db, Command::CreateSecret { secret, version }).expect("create");
        let before = version_keys(&db);

        let backup = super::super::backup::BackupData {
            version: super::super::backup::BACKUP_VERSION,
            secrets: vec![("x\u{0}y".to_string(), vec![1, 2, 3])],
            ..Default::default()
        };
        let result = apply(
            &db,
            Command::RestoreDatabase {
                data: Box::new(backup),
            },
        );

        assert!(matches!(result, Err(StoreError::Conflict(_))));
        assert_eq!(
            version_keys(&db),
            before,
            "a refused restore changes nothing"
        );
    }

    #[test]
    fn a_second_token_may_not_reuse_a_fingerprint() {
        let db = tmp_db();
        apply(
            &db,
            Command::AddToken {
                token: sample_token("first", vec![1, 2, 3]),
            },
        )
        .expect("first token");

        let result = apply(
            &db,
            Command::AddToken {
                token: sample_token("second", vec![1, 2, 3]),
            },
        );
        assert!(
            matches!(result, Err(StoreError::Conflict(_))),
            "a reused fingerprint must not overwrite the first token"
        );

        let rtx = db.begin_read().expect("begin read");
        let tokens = rtx.open_table(TOKENS).expect("open tokens");
        let stored: TokenRecord = decode(
            tokens
                .get([1, 2, 3].as_slice())
                .expect("get")
                .expect("token present")
                .value(),
        )
        .expect("decode");
        assert_eq!(stored.name, "first");
    }

    #[test]
    fn an_audit_row_above_the_plausible_range_does_not_stop_appends() {
        let db = tmp_db();
        {
            let wtx = db.begin_write().expect("begin write");
            {
                let mut table = wtx.open_table(AUDIT).expect("open audit");
                table
                    .insert(
                        u64::MAX,
                        encode(&audit_entry("planted")).unwrap().as_slice(),
                    )
                    .expect("insert");
            }
            wtx.commit().expect("commit");
        }

        for action in ["create", "rotate", "delete"] {
            apply(
                &db,
                Command::AppendAudit {
                    entry: audit_entry(action),
                },
            )
            .expect("append");
        }

        assert_eq!(
            audit_keys(&db),
            vec![0, 1, 2, u64::MAX],
            "each append must take the next free key instead of overwriting"
        );
    }

    #[test]
    fn create_rejects_a_name_outside_the_allowed_characters() {
        let db = tmp_db();
        let (mut secret, version) = sample();
        secret.name = "x\u{0}y".to_string();
        let result = apply(&db, Command::CreateSecret { secret, version });
        assert!(
            matches!(result, Err(StoreError::Conflict(_))),
            "a name with a version-key separator must be refused"
        );
        assert!(version_keys(&db).is_empty(), "nothing may be written");
    }

    #[test]
    fn create_rejects_a_version_below_one() {
        let db = tmp_db();
        let (secret, mut version) = sample();
        version.version = 0;
        let result = apply(&db, Command::CreateSecret { secret, version });
        assert!(matches!(result, Err(StoreError::Conflict(_))));
        assert!(version_keys(&db).is_empty(), "nothing may be written");
    }

    #[test]
    fn delete_leaves_another_secrets_rows_alone() {
        let db = tmp_db();
        let (mut secret, mut version) = sample();
        secret.name = "x".to_string();
        version.aad = b"x:1".to_vec();
        apply(
            &db,
            Command::CreateSecret {
                secret,
                version: version.clone(),
            },
        )
        .expect("create");

        let intruder = version_key("x\u{0}y", 1);
        insert_raw_version(&db, &intruder, &version);

        apply(
            &db,
            Command::DeleteSecret {
                name: "x".to_string(),
            },
        )
        .expect("delete");

        assert_eq!(
            version_keys(&db),
            vec![intruder],
            "only the deleted secret's own rows may be removed"
        );
    }

    #[test]
    fn rewrap_version_swaps_wrapping_and_preserves_payload() {
        let db = tmp_db();
        let (secret, version) = sample();
        apply(&db, Command::CreateSecret { secret, version }).expect("create");

        apply(
            &db,
            Command::RewrapVersion {
                name: "db/password".to_string(),
                version: 1,
                kms_key_id: "new-key".to_string(),
                wrapped_dek: vec![7, 8, 9, 10],
                wrapped_rotation_at: 100,
            },
        )
        .expect("rewrap");

        let got = read_version(&db, "db/password", 1);
        assert_eq!(got.kms_key_id, "new-key");
        assert_eq!(got.wrapped_dek, vec![7, 8, 9, 10]);
        assert_eq!(got.wrapped_rotation_at, Some(100));
        assert_eq!(
            got.ciphertext,
            vec![9, 9, 9],
            "ciphertext must be untouched"
        );
        assert_eq!(got.nonce, vec![4; 24], "nonce must be untouched");
        assert_eq!(got.aad, b"db/password:1".to_vec(), "aad must be untouched");
    }

    #[test]
    fn rewrap_version_is_idempotent_and_never_errors() {
        let db = tmp_db();
        let (secret, version) = sample();
        apply(&db, Command::CreateSecret { secret, version }).expect("create");

        apply(
            &db,
            Command::RewrapVersion {
                name: "db/password".to_string(),
                version: 1,
                kms_key_id: "gen100".to_string(),
                wrapped_dek: vec![1],
                wrapped_rotation_at: 100,
            },
        )
        .expect("first rewrap");

        apply(
            &db,
            Command::RewrapVersion {
                name: "db/password".to_string(),
                version: 1,
                kms_key_id: "gen100-replay".to_string(),
                wrapped_dek: vec![2],
                wrapped_rotation_at: 100,
            },
        )
        .expect("replay rewrap");

        let got = read_version(&db, "db/password", 1);
        assert_eq!(got.kms_key_id, "gen100", "replay must not overwrite");
        assert_eq!(got.wrapped_dek, vec![1]);

        apply(
            &db,
            Command::RewrapVersion {
                name: "db/password".to_string(),
                version: 99,
                kms_key_id: "x".to_string(),
                wrapped_dek: vec![0],
                wrapped_rotation_at: 200,
            },
        )
        .expect("missing version must not error");
    }

    #[test]
    fn set_kms_rewrap_state_roundtrips() {
        let db = tmp_db();
        apply(
            &db,
            Command::SetKmsRewrapState {
                state: KmsRewrapState {
                    last_completed_rotation_at: 1234,
                    last_swept_at: 5,
                    updated_at: 6,
                },
            },
        )
        .expect("set state");

        let rtx = db.begin_read().expect("begin read");
        let table = rtx.open_table(KMS_REWRAP).expect("open kms_rewrap");
        let value = table
            .get(KMS_REWRAP_STATE_KEY)
            .expect("get")
            .expect("state present");
        let state: KmsRewrapState = decode(value.value()).expect("decode state");
        assert_eq!(state.last_completed_rotation_at, 1234);
    }
}

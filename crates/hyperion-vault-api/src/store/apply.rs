use anyhow::anyhow;
use redb::{ReadableTable, WriteTransaction};

use super::codec::{decode, encode};
use super::engine::{
    version_key, version_lower, version_upper, AUDIT, LOCKOUTS, ROLES, SECRETS, TOKENS,
    TOKENS_BY_NAME, VERSIONS,
};
use super::model::{
    Command, LockoutRecord, NextRotation, SecretRecord, StoreError, StoreResult, TokenRecord,
    VersionRecord,
};

fn err<E: std::fmt::Debug>(e: E) -> StoreError {
    StoreError::Internal(anyhow!("redb: {e:?}"))
}

pub fn apply_command(wtx: &WriteTransaction, node_id: u64, command: &Command) -> StoreResult<()> {
    match command {
        Command::CreateSecret { secret, version } => {
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
                    keys.push(key.value().to_string());
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

        Command::AppendAudit { entry } => {
            let mut audit = wtx.open_table(AUDIT).map_err(err)?;
            let next: u64 = match audit.last().map_err(err)? {
                Some((key, _value)) => key.value() + 1,
                None => 0,
            };
            let mut entry = entry.clone();
            entry.node_id = node_id;
            audit
                .insert(next, encode(&entry)?.as_slice())
                .map_err(err)?;
            Ok(())
        }

        Command::RecordAuthFailure {
            ip,
            now,
            max,
            window_secs,
            lockout_secs,
        } => {
            let mut locks = wtx.open_table(LOCKOUTS).map_err(err)?;
            let mut record: LockoutRecord = match locks.get(ip.as_str()).map_err(err)? {
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
                .insert(ip.as_str(), encode(&record)?.as_slice())
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

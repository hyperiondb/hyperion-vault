use std::net::{IpAddr, Ipv4Addr};

use anyhow::anyhow;
use zeroize::Zeroizing;

use hyperion_vault_core::auth;
use hyperion_vault_core::crypto::{generate_nonce, open, seal, Dek, NONCE_LEN};
use hyperion_vault_core::types::aad_for;
use hyperion_vault_core::{SecretFormat, SecretKind};

use crate::clock::{now_unix, rfc3339, rfc3339_opt};
use crate::dto::{
    CreateSecretRequest, SecretMetadata, SecretValue, UpdateSecretRequest, UserPass, VerifyResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::lockout;
use crate::state::AppState;
use crate::store::{AuditEntry, Command, NextRotation, SecretRecord, VersionRecord};

const MAX_NAME_LEN: usize = 255;
const MAX_VALUE_LEN: usize = 1 << 16;
const MAX_BATCH: usize = 256;

struct Payload {
    format: SecretFormat,
    bytes: Vec<u8>,
    value: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

pub async fn create_secret(
    state: &AppState,
    actor: &str,
    req: CreateSecretRequest,
) -> ApiResult<SecretValue> {
    validate_name(&req.name)?;
    let grace = normalize_grace(req.grace_period_secs)?;

    if req.kind == SecretKind::Automatic {
        match req.rotation_interval_secs {
            Some(secs) if secs > 0 => {}
            _ => {
                return Err(ApiError::BadRequest(
                    "automatic secret requires positive 'rotation_interval_secs'".into(),
                ))
            }
        }
    }

    let payload = build_create_payload(&req)?;
    let now = now_unix();
    let version = seal_version(state, &req.name, 1, &payload.bytes, now).await?;

    let next_rotation_at = if req.kind == SecretKind::Automatic {
        req.rotation_interval_secs.map(|secs| now + secs)
    } else {
        None
    };

    let secret = SecretRecord {
        name: req.name.clone(),
        kind: req.kind,
        format: payload.format,
        description: req.description.clone(),
        rotation_interval_secs: req.rotation_interval_secs,
        grace_secs: grace,
        current_version: 1,
        next_rotation_at,
        created_at: now,
        updated_at: now,
    };

    state
        .store
        .apply(Command::CreateSecret { secret, version })
        .await?;
    audit(state, Some(actor), None, "create", Some(&req.name), "ok").await;

    Ok(SecretValue {
        name: req.name,
        kind: req.kind,
        format: payload.format,
        version: 1,
        value: payload.value,
        username: payload.username,
        password: payload.password,
        created_at: rfc3339(now),
    })
}

pub async fn get_secret(
    state: &AppState,
    name: &str,
    client_ip: Ipv4Addr,
) -> ApiResult<SecretValue> {
    let (secret, version) = match state.store.current_version(name.to_string()).await? {
        Some(pair) => pair,
        None => {
            audit(state, None, Some(client_ip), "get", Some(name), "not_found").await;
            return Err(ApiError::NotFound);
        }
    };

    let plaintext = open_version(state, name, version.version, &version).await?;
    let (value, username, password) = decode_payload(secret.format, plaintext)?;

    audit(state, None, Some(client_ip), "get", Some(name), "ok").await;

    Ok(SecretValue {
        name: name.to_string(),
        kind: secret.kind,
        format: secret.format,
        version: version.version,
        value,
        username,
        password,
        created_at: rfc3339(version.created_at),
    })
}

pub async fn list_secrets(state: &AppState) -> ApiResult<Vec<SecretMetadata>> {
    Ok(state
        .store
        .list_secrets()
        .await?
        .into_iter()
        .map(to_metadata)
        .collect())
}

pub async fn get_secrets(
    state: &AppState,
    names: Vec<String>,
    client_ip: Ipv4Addr,
) -> ApiResult<Vec<SecretValue>> {
    if names.len() > MAX_BATCH {
        return Err(ApiError::BadRequest(format!(
            "batch too large: {} names (max {MAX_BATCH})",
            names.len()
        )));
    }

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        match state.store.current_version(name.clone()).await? {
            Some((secret, version)) => {
                let plaintext = open_version(state, &name, version.version, &version).await?;
                let (value, username, password) = decode_payload(secret.format, plaintext)?;
                audit(state, None, Some(client_ip), "get", Some(&name), "ok").await;
                out.push(SecretValue {
                    name,
                    kind: secret.kind,
                    format: secret.format,
                    version: version.version,
                    value,
                    username,
                    password,
                    created_at: rfc3339(version.created_at),
                });
            }
            None => {
                audit(
                    state,
                    None,
                    Some(client_ip),
                    "get",
                    Some(&name),
                    "not_found",
                )
                .await;
            }
        }
    }
    Ok(out)
}

pub async fn update_secret(
    state: &AppState,
    actor: &str,
    name: &str,
    req: UpdateSecretRequest,
) -> ApiResult<SecretMetadata> {
    if let Some(secs) = req.rotation_interval_secs {
        if secs <= 0 {
            return Err(ApiError::BadRequest(
                "rotation_interval_secs must be positive".into(),
            ));
        }
    }
    if let Some(secs) = req.grace_period_secs {
        if secs < 0 {
            return Err(ApiError::BadRequest(
                "grace_period_secs must not be negative".into(),
            ));
        }
    }

    let secret = state
        .store
        .secret(name.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;
    let format = secret.format;
    let kind = secret.kind;
    let current_version = secret.current_version;

    match format {
        SecretFormat::Opaque if req.username.is_some() || req.password.is_some() => {
            return Err(ApiError::BadRequest(
                "secret is opaque; use 'value', not 'username'/'password'".into(),
            ))
        }
        SecretFormat::Userpass if req.value.is_some() => {
            return Err(ApiError::BadRequest(
                "secret is userpass; use 'username'/'password', not 'value'".into(),
            ))
        }
        _ => {}
    }

    let secret_changed = match format {
        SecretFormat::Opaque => req.value.is_some(),
        SecretFormat::Userpass => req.username.is_some() || req.password.is_some(),
    };

    let now = now_unix();
    let effective_interval = req
        .rotation_interval_secs
        .or(secret.rotation_interval_secs)
        .unwrap_or(0);

    let command = if secret_changed {
        let bytes = match format {
            SecretFormat::Opaque => {
                let value = req.value.clone().unwrap_or_default();
                validate_value(&value)?;
                value.into_bytes()
            }
            SecretFormat::Userpass => {
                let current = load_userpass(state, name, current_version).await?;
                let username = req.username.clone().unwrap_or(current.username);
                let password = req.password.clone().unwrap_or(current.password);
                validate_field("username", &username)?;
                validate_field("password", &password)?;
                encode_userpass(&username, &password)
            }
        };

        let new_version = current_version + 1;
        let version = seal_version(state, name, new_version, &bytes, now).await?;
        let reset_timer = kind == SecretKind::Automatic;
        Command::PutVersion {
            name: name.to_string(),
            expected_current: current_version,
            version,
            supersede_expires_at: Some(now + secret.grace_secs),
            set_description: req.description.clone(),
            set_rotation_interval_secs: req.rotation_interval_secs,
            set_grace_secs: req.grace_period_secs,
            next_rotation_at: if reset_timer {
                NextRotation::Set(Some(now + effective_interval))
            } else {
                NextRotation::Keep
            },
            updated_at: now,
        }
    } else {
        let reset_timer = kind == SecretKind::Automatic && req.rotation_interval_secs.is_some();
        Command::UpdateMeta {
            name: name.to_string(),
            expected_current: current_version,
            set_description: req.description.clone(),
            set_rotation_interval_secs: req.rotation_interval_secs,
            set_grace_secs: req.grace_period_secs,
            next_rotation_at: if reset_timer {
                NextRotation::Set(Some(now + effective_interval))
            } else {
                NextRotation::Keep
            },
            updated_at: now,
        }
    };

    state.store.apply(command).await?;
    audit(state, Some(actor), None, "update", Some(name), "ok").await;

    load_metadata(state, name).await
}

pub async fn delete_secret(state: &AppState, actor: &str, name: &str) -> ApiResult<()> {
    state
        .store
        .apply(Command::DeleteSecret {
            name: name.to_string(),
        })
        .await?;
    audit(state, Some(actor), None, "delete", Some(name), "ok").await;
    Ok(())
}

pub async fn rotate(
    state: &AppState,
    actor: &str,
    client_ip: Option<Ipv4Addr>,
    name: &str,
) -> ApiResult<SecretValue> {
    let secret = state
        .store
        .secret(name.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;

    if secret.kind != SecretKind::Automatic {
        return Err(ApiError::BadRequest(
            "only automatic secrets can be rotated; use update for manual secrets".into(),
        ));
    }

    let current_version = secret.current_version;
    let new_version = current_version + 1;
    let now = now_unix();

    let payload = match secret.format {
        SecretFormat::Opaque => {
            let value = auth::generate_token();
            Payload {
                format: SecretFormat::Opaque,
                bytes: value.clone().into_bytes(),
                value: Some(value),
                username: None,
                password: None,
            }
        }
        SecretFormat::Userpass => {
            let current = load_userpass(state, name, current_version).await?;
            let password = auth::generate_token();
            let bytes = encode_userpass(&current.username, &password);
            Payload {
                format: SecretFormat::Userpass,
                bytes,
                value: None,
                username: Some(current.username),
                password: Some(password),
            }
        }
    };

    let version = seal_version(state, name, new_version, &payload.bytes, now).await?;
    let interval = secret.rotation_interval_secs.unwrap_or(0);

    state
        .store
        .apply(Command::PutVersion {
            name: name.to_string(),
            expected_current: current_version,
            version,
            supersede_expires_at: Some(now + secret.grace_secs),
            set_description: None,
            set_rotation_interval_secs: None,
            set_grace_secs: None,
            next_rotation_at: NextRotation::Set(Some(now + interval)),
            updated_at: now,
        })
        .await?;

    audit(state, Some(actor), client_ip, "rotate", Some(name), "ok").await;

    Ok(SecretValue {
        name: name.to_string(),
        kind: secret.kind,
        format: secret.format,
        version: new_version,
        value: payload.value,
        username: payload.username,
        password: payload.password,
        created_at: rfc3339(now),
    })
}

pub async fn verify(
    state: &AppState,
    name: &str,
    client_ip: Ipv4Addr,
    presented: &str,
) -> ApiResult<VerifyResponse> {
    let now = now_unix();

    if let Some(secret) = state.store.secret(name.to_string()).await? {
        let versions = state.store.live_versions(name.to_string(), now).await?;
        for version in versions {
            let plaintext = open_version(state, name, version.version, &version).await?;
            let matches = match secret.format {
                SecretFormat::Opaque => auth::fingerprints_match(presented.as_bytes(), &plaintext),
                SecretFormat::Userpass => match decode_userpass(&plaintext) {
                    Ok(up) => {
                        auth::fingerprints_match(presented.as_bytes(), up.password.as_bytes())
                    }
                    Err(_) => false,
                },
            };
            if matches {
                audit(state, None, Some(client_ip), "verify", Some(name), "valid").await;
                return Ok(VerifyResponse {
                    valid: true,
                    version: Some(version.version),
                });
            }
        }
    }

    audit(
        state,
        None,
        Some(client_ip),
        "verify",
        Some(name),
        "invalid",
    )
    .await;
    lockout::record(state, Some(IpAddr::V4(client_ip))).await;
    Ok(VerifyResponse {
        valid: false,
        version: None,
    })
}

fn to_metadata(secret: SecretRecord) -> SecretMetadata {
    SecretMetadata {
        name: secret.name,
        kind: secret.kind,
        format: secret.format,
        description: secret.description,
        version: secret.current_version,
        rotation_interval_secs: secret.rotation_interval_secs,
        grace_period_secs: secret.grace_secs,
        next_rotation_at: rfc3339_opt(secret.next_rotation_at),
        created_at: rfc3339(secret.created_at),
        updated_at: rfc3339(secret.updated_at),
    }
}

async fn load_metadata(state: &AppState, name: &str) -> ApiResult<SecretMetadata> {
    let secret = state
        .store
        .secret(name.to_string())
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(to_metadata(secret))
}

fn build_create_payload(req: &CreateSecretRequest) -> ApiResult<Payload> {
    let wants_userpass = req.username.is_some() || req.password.is_some();
    if wants_userpass {
        if req.value.is_some() {
            return Err(ApiError::BadRequest(
                "provide either 'value' or 'username'/'password', not both".into(),
            ));
        }
        let username = req
            .username
            .clone()
            .ok_or_else(|| ApiError::BadRequest("userpass secret requires 'username'".into()))?;
        validate_field("username", &username)?;
        let password = match (req.kind, req.password.clone()) {
            (_, Some(password)) => {
                validate_field("password", &password)?;
                password
            }
            (SecretKind::Manual, None) => {
                return Err(ApiError::BadRequest(
                    "manual userpass secret requires 'password'".into(),
                ))
            }
            (SecretKind::Automatic, None) => auth::generate_token(),
        };
        let bytes = encode_userpass(&username, &password);
        Ok(Payload {
            format: SecretFormat::Userpass,
            bytes,
            value: None,
            username: Some(username),
            password: Some(password),
        })
    } else {
        let value = match (req.kind, req.value.clone()) {
            (_, Some(value)) => {
                validate_value(&value)?;
                value
            }
            (SecretKind::Manual, None) => {
                return Err(ApiError::BadRequest(
                    "manual secret requires 'value'".into(),
                ))
            }
            (SecretKind::Automatic, None) => auth::generate_token(),
        };
        Ok(Payload {
            format: SecretFormat::Opaque,
            bytes: value.clone().into_bytes(),
            value: Some(value),
            username: None,
            password: None,
        })
    }
}

fn encode_userpass(username: &str, password: &str) -> Vec<u8> {
    serde_json::to_vec(&UserPass {
        username: username.to_string(),
        password: password.to_string(),
    })
    .expect("userpass serialization is infallible")
}

fn decode_userpass(bytes: &[u8]) -> ApiResult<UserPass> {
    serde_json::from_slice(bytes)
        .map_err(|_| ApiError::Internal(anyhow!("stored userpass payload is malformed")))
}

fn decode_payload(
    format: SecretFormat,
    plaintext: Zeroizing<Vec<u8>>,
) -> ApiResult<(Option<String>, Option<String>, Option<String>)> {
    match format {
        SecretFormat::Opaque => {
            let value = std::str::from_utf8(&plaintext)
                .map_err(|_| ApiError::Internal(anyhow!("decrypted value is not valid UTF-8")))?
                .to_string();
            Ok((Some(value), None, None))
        }
        SecretFormat::Userpass => {
            let up = decode_userpass(&plaintext)?;
            Ok((None, Some(up.username), Some(up.password)))
        }
    }
}

async fn load_userpass(state: &AppState, name: &str, version: i32) -> ApiResult<UserPass> {
    let record = state
        .store
        .version(name.to_string(), version)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow!("current version row missing")))?;
    let plaintext = open_version(state, name, version, &record).await?;
    decode_userpass(&plaintext)
}

async fn seal_version(
    state: &AppState,
    name: &str,
    version: i32,
    plaintext: &[u8],
    now: i64,
) -> ApiResult<VersionRecord> {
    let aad = aad_for(name, version);
    let version_str = version.to_string();
    let context = [("secret", name), ("version", version_str.as_str())];
    let data_key = state.kms.generate_data_key(&context).await?;
    let nonce = generate_nonce();
    let ciphertext = seal(&data_key.plaintext, &nonce, &aad, plaintext)?;
    let generation = state
        .store
        .kms_rewrap_state()
        .await?
        .map(|s| s.last_completed_rotation_at)
        .unwrap_or(0);
    Ok(VersionRecord {
        version,
        kms_key_id: data_key.key_id,
        wrapped_dek: data_key.wrapped,
        nonce: nonce.to_vec(),
        ciphertext,
        aad,
        created_at: now,
        expires_at: None,
        wrapped_rotation_at: Some(generation),
    })
}

async fn open_version(
    state: &AppState,
    name: &str,
    version: i32,
    record: &VersionRecord,
) -> ApiResult<Zeroizing<Vec<u8>>> {
    let aad = aad_for(name, version);
    if record.aad != aad {
        return Err(ApiError::Internal(anyhow!(
            "stored aad does not match secret identity (possible tampering)"
        )));
    }
    let nonce: [u8; NONCE_LEN] = record
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow!("stored nonce has invalid length")))?;
    let dek: Dek = match state.dek_cache.get(&record.wrapped_dek) {
        Some(dek) => dek,
        None => {
            let version_str = version.to_string();
            let context = [("secret", name), ("version", version_str.as_str())];
            let dek = state
                .kms
                .decrypt_data_key(&record.wrapped_dek, &record.kms_key_id, &context)
                .await?;
            state.dek_cache.put(record.wrapped_dek.clone(), dek.clone());
            dek
        }
    };
    Ok(open(&dek, &nonce, &aad, &record.ciphertext)?)
}

pub(crate) async fn audit(
    state: &AppState,
    actor: Option<&str>,
    client_ip: Option<Ipv4Addr>,
    action: &str,
    secret_name: Option<&str>,
    outcome: &str,
) {
    let entry = AuditEntry {
        at: now_unix(),
        actor: actor.map(|s| s.to_string()),
        client_ip: client_ip.map(|ip| ip.to_string()),
        action: action.to_string(),
        secret_name: secret_name.map(|s| s.to_string()),
        outcome: outcome.to_string(),
        node_id: 0,
    };
    if let Err(err) = state.store.apply(Command::AppendAudit { entry }).await {
        tracing::warn!(
            error = %err,
            actor = ?actor,
            action,
            secret_name = ?secret_name,
            outcome,
            "audit not persisted; recorded to log only"
        );
    }
}

fn validate_name(name: &str) -> ApiResult<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest(
            "secret name must be between 1 and 255 characters".into(),
        ));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.'));
    if !ok {
        return Err(ApiError::BadRequest(
            "secret name may contain only [A-Za-z0-9-_/.]".into(),
        ));
    }
    Ok(())
}

fn validate_value(value: &str) -> ApiResult<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(ApiError::BadRequest("secret value is too large".into()));
    }
    Ok(())
}

fn validate_field(label: &str, value: &str) -> ApiResult<()> {
    if value.is_empty() {
        return Err(ApiError::BadRequest(format!("{label} must not be empty")));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(ApiError::BadRequest(format!("{label} is too large")));
    }
    Ok(())
}

fn normalize_grace(grace: Option<i64>) -> ApiResult<i64> {
    match grace {
        None => Ok(0),
        Some(secs) if secs >= 0 => Ok(secs),
        Some(_) => Err(ApiError::BadRequest(
            "grace_period_secs must not be negative".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userpass_payload_roundtrips() {
        let bytes = encode_userpass("alice", "s3cr3t");
        let up = decode_userpass(&bytes).expect("decode");
        assert_eq!(up.username, "alice");
        assert_eq!(up.password, "s3cr3t");
    }

    #[test]
    fn decode_payload_opaque_returns_value() {
        let (value, username, password) =
            decode_payload(SecretFormat::Opaque, Zeroizing::new(b"raw".to_vec())).expect("opaque");
        assert_eq!(value.as_deref(), Some("raw"));
        assert!(username.is_none() && password.is_none());
    }

    #[test]
    fn decode_payload_userpass_returns_pair() {
        let bytes = encode_userpass("bob", "pw");
        let (value, username, password) =
            decode_payload(SecretFormat::Userpass, Zeroizing::new(bytes)).expect("userpass");
        assert!(value.is_none());
        assert_eq!(username.as_deref(), Some("bob"));
        assert_eq!(password.as_deref(), Some("pw"));
    }

    #[test]
    fn decode_userpass_rejects_non_json() {
        assert!(decode_userpass(b"not-json").is_err());
    }
}

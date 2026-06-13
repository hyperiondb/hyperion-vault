use std::net::Ipv4Addr;

use anyhow::anyhow;
use tokio_postgres::error::SqlState;

use hyperion_vault_core::auth;
use hyperion_vault_core::crypto::{generate_nonce, open, seal, Dek, NONCE_LEN};
use hyperion_vault_core::types::aad_for;
use hyperion_vault_core::SecretKind;

use crate::dto::{
    CreateSecretRequest, SecretMetadata, SecretValue, UpdateSecretRequest, VerifyResponse,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const MAX_NAME_LEN: usize = 255;
const MAX_VALUE_LEN: usize = 1 << 16;

struct Sealed {
    key_id: String,
    wrapped_dek: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

pub async fn create_secret(
    state: &AppState,
    actor: &str,
    req: CreateSecretRequest,
) -> ApiResult<SecretValue> {
    validate_name(&req.name)?;
    let grace = normalize_grace(req.grace_period_secs)?;

    let value = match (req.kind, req.value.clone()) {
        (_, Some(value)) => {
            validate_value(&value)?;
            value
        }
        (SecretKind::Manual, None) => {
            return Err(ApiError::BadRequest("manual secret requires 'value'".into()))
        }
        (SecretKind::Automatic, None) => auth::generate_token(),
    };

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

    let sealed = seal_version(state, &req.name, 1, value.as_bytes()).await?;

    let mut client = state.db.writer().await?;
    let tx = client.transaction().await?;

    let row = tx
        .query_one(
            "INSERT INTO vault.secrets \
                (name, kind, description, rotation_interval, grace_period, current_version, next_rotation_at) \
             VALUES ($1, $2::vault.secret_kind, $3, \
                CASE WHEN $4::bigint IS NULL THEN NULL ELSE make_interval(secs => $4::bigint) END, \
                make_interval(secs => $5::bigint), 1, \
                CASE WHEN $4::bigint IS NULL THEN NULL ELSE now() + make_interval(secs => $4::bigint) END) \
             RETURNING id::text, created_at::text",
            &[
                &req.name,
                &req.kind.as_str(),
                &req.description,
                &req.rotation_interval_secs,
                &grace,
            ],
        )
        .await
        .map_err(|err| insert_conflict(err, &req.name))?;

    let id: String = row.get(0);
    let created_at: String = row.get(1);

    insert_version(&tx, &id, 1, &sealed).await?;
    tx.commit().await?;

    audit(state, Some(actor), None, "create", Some(&req.name), "ok").await;

    Ok(SecretValue {
        name: req.name,
        kind: req.kind,
        version: 1,
        value,
        created_at,
    })
}

pub async fn get_secret(
    state: &AppState,
    name: &str,
    client_ip: Ipv4Addr,
) -> ApiResult<SecretValue> {
    let client = state.db.reader().await?;
    let row = client
        .query_opt(
            "SELECT s.kind::text, v.version, v.kms_key_id, v.wrapped_dek, v.nonce, v.ciphertext, v.aad, v.created_at::text \
             FROM vault.secrets s \
             JOIN vault.secret_versions v ON v.secret_id = s.id AND v.version = s.current_version \
             WHERE s.name = $1",
            &[&name],
        )
        .await?;

    let row = match row {
        Some(row) => row,
        None => {
            audit(state, None, Some(client_ip), "get", Some(name), "not_found").await;
            return Err(ApiError::NotFound);
        }
    };

    let kind = parse_kind(row.get::<_, String>(0))?;
    let version: i32 = row.get(1);
    let key_id: String = row.get(2);
    let wrapped: Vec<u8> = row.get(3);
    let nonce: Vec<u8> = row.get(4);
    let ciphertext: Vec<u8> = row.get(5);
    let aad: Vec<u8> = row.get(6);
    let created_at: String = row.get(7);

    let expected_aad = aad_for(name, version);
    if aad != expected_aad {
        return Err(ApiError::Internal(anyhow!(
            "stored aad does not match secret identity (possible tampering)"
        )));
    }

    let plaintext = open_version(state, &key_id, &wrapped, &nonce, &aad, &ciphertext).await?;
    let value = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal(anyhow!("decrypted value is not valid UTF-8")))?;

    audit(state, None, Some(client_ip), "get", Some(name), "ok").await;

    Ok(SecretValue {
        name: name.to_string(),
        kind,
        version,
        value,
        created_at,
    })
}

pub async fn list_secrets(state: &AppState) -> ApiResult<Vec<SecretMetadata>> {
    let client = state.db.reader().await?;
    let rows = client
        .query(
            "SELECT name, kind::text, description, current_version, \
                EXTRACT(EPOCH FROM rotation_interval)::bigint, \
                EXTRACT(EPOCH FROM grace_period)::bigint, \
                next_rotation_at::text, created_at::text, updated_at::text \
             FROM vault.secrets ORDER BY name",
            &[],
        )
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(SecretMetadata {
            name: row.get(0),
            kind: parse_kind(row.get::<_, String>(1))?,
            description: row.get(2),
            version: row.get(3),
            rotation_interval_secs: row.get(4),
            grace_period_secs: row.get::<_, Option<i64>>(5).unwrap_or(0),
            next_rotation_at: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
        });
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
    let grace_override = normalize_grace(req.grace_period_secs.map(Some).unwrap_or(None))?;
    let _ = grace_override;

    let mut client = state.db.writer().await?;
    let tx = client.transaction().await?;

    let row = tx
        .query_opt(
            "SELECT id::text, kind::text, current_version, \
                EXTRACT(EPOCH FROM grace_period)::bigint \
             FROM vault.secrets WHERE name = $1 FOR UPDATE",
            &[&name],
        )
        .await?;

    let row = match row {
        Some(row) => row,
        None => return Err(ApiError::NotFound),
    };

    let id: String = row.get(0);
    let kind = parse_kind(row.get::<_, String>(1))?;
    let current_version: i32 = row.get(2);
    let grace_secs: i64 = row.get::<_, Option<i64>>(3).unwrap_or(0);

    let mut new_version = current_version;
    if let Some(value) = req.value.clone() {
        validate_value(&value)?;
        new_version = current_version + 1;
        let sealed = seal_version(state, name, new_version, value.as_bytes()).await?;
        insert_version(&tx, &id, new_version, &sealed).await?;
        tx.execute(
            "UPDATE vault.secret_versions \
             SET expires_at = now() + make_interval(secs => $3::bigint) \
             WHERE secret_id = $1::uuid AND version = $2 AND expires_at IS NULL",
            &[&id, &current_version, &grace_secs],
        )
        .await?;
    }

    let reset_timer = kind == SecretKind::Automatic
        && (req.value.is_some() || req.rotation_interval_secs.is_some());

    tx.execute(
        "UPDATE vault.secrets SET \
            description = COALESCE($2, description), \
            rotation_interval = CASE WHEN $3::bigint IS NULL THEN rotation_interval \
                ELSE make_interval(secs => $3::bigint) END, \
            grace_period = CASE WHEN $4::bigint IS NULL THEN grace_period \
                ELSE make_interval(secs => $4::bigint) END, \
            current_version = $5, \
            next_rotation_at = CASE WHEN $6 THEN \
                now() + COALESCE(make_interval(secs => $3::bigint), rotation_interval) \
                ELSE next_rotation_at END, \
            updated_at = now() \
         WHERE name = $1",
        &[
            &name,
            &req.description,
            &req.rotation_interval_secs,
            &req.grace_period_secs,
            &new_version,
            &reset_timer,
        ],
    )
    .await?;

    tx.commit().await?;
    audit(state, Some(actor), None, "update", Some(name), "ok").await;

    load_metadata(state, name).await
}

pub async fn delete_secret(state: &AppState, actor: &str, name: &str) -> ApiResult<()> {
    let client = state.db.writer().await?;
    let affected = client
        .execute("DELETE FROM vault.secrets WHERE name = $1", &[&name])
        .await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    audit(state, Some(actor), None, "delete", Some(name), "ok").await;
    Ok(())
}

pub async fn rotate(
    state: &AppState,
    actor: &str,
    client_ip: Option<Ipv4Addr>,
    name: &str,
) -> ApiResult<SecretValue> {
    let mut client = state.db.writer().await?;
    let tx = client.transaction().await?;

    let row = tx
        .query_opt(
            "SELECT id::text, kind::text, current_version, \
                EXTRACT(EPOCH FROM grace_period)::bigint, \
                EXTRACT(EPOCH FROM rotation_interval)::bigint \
             FROM vault.secrets WHERE name = $1 FOR UPDATE",
            &[&name],
        )
        .await?;

    let row = match row {
        Some(row) => row,
        None => return Err(ApiError::NotFound),
    };

    let id: String = row.get(0);
    let kind = parse_kind(row.get::<_, String>(1))?;
    let current_version: i32 = row.get(2);
    let grace_secs: i64 = row.get::<_, Option<i64>>(3).unwrap_or(0);
    let interval_secs: Option<i64> = row.get(4);

    if kind != SecretKind::Automatic {
        return Err(ApiError::BadRequest(
            "only automatic secrets can be rotated; use update for manual secrets".into(),
        ));
    }

    let value = auth::generate_token();
    let new_version = current_version + 1;
    let sealed = seal_version(state, name, new_version, value.as_bytes()).await?;
    insert_version(&tx, &id, new_version, &sealed).await?;

    tx.execute(
        "UPDATE vault.secret_versions \
         SET expires_at = now() + make_interval(secs => $3::bigint) \
         WHERE secret_id = $1::uuid AND version = $2 AND expires_at IS NULL",
        &[&id, &current_version, &grace_secs],
    )
    .await?;

    let created_at_row = tx
        .query_one(
            "UPDATE vault.secrets SET \
                current_version = $2, \
                next_rotation_at = now() + make_interval(secs => $3::bigint), \
                updated_at = now() \
             WHERE id = $1::uuid \
             RETURNING (SELECT created_at::text FROM vault.secret_versions \
                 WHERE secret_id = $1::uuid AND version = $2)",
            &[&id, &new_version, &interval_secs.unwrap_or(0)],
        )
        .await?;
    let created_at: String = created_at_row.get(0);

    tx.commit().await?;
    audit(state, Some(actor), client_ip, "rotate", Some(name), "ok").await;

    Ok(SecretValue {
        name: name.to_string(),
        kind,
        version: new_version,
        value,
        created_at,
    })
}

pub async fn verify(
    state: &AppState,
    name: &str,
    client_ip: Ipv4Addr,
    presented: &str,
) -> ApiResult<VerifyResponse> {
    let client = state.db.reader().await?;
    let rows = client
        .query(
            "SELECT v.version, v.kms_key_id, v.wrapped_dek, v.nonce, v.ciphertext, v.aad \
             FROM vault.secret_versions v \
             JOIN vault.secrets s ON s.id = v.secret_id \
             WHERE s.name = $1 AND (v.expires_at IS NULL OR v.expires_at > now()) \
             ORDER BY v.version DESC",
            &[&name],
        )
        .await?;

    for row in rows {
        let version: i32 = row.get(0);
        let key_id: String = row.get(1);
        let wrapped: Vec<u8> = row.get(2);
        let nonce: Vec<u8> = row.get(3);
        let ciphertext: Vec<u8> = row.get(4);
        let aad: Vec<u8> = row.get(5);

        let plaintext = open_version(state, &key_id, &wrapped, &nonce, &aad, &ciphertext).await?;
        if auth::fingerprints_match(presented.as_bytes(), &plaintext) {
            audit(state, None, Some(client_ip), "verify", Some(name), "valid").await;
            return Ok(VerifyResponse {
                valid: true,
                version: Some(version),
            });
        }
    }

    audit(state, None, Some(client_ip), "verify", Some(name), "invalid").await;
    Ok(VerifyResponse {
        valid: false,
        version: None,
    })
}

async fn seal_version(
    state: &AppState,
    name: &str,
    version: i32,
    plaintext: &[u8],
) -> ApiResult<Sealed> {
    let aad = aad_for(name, version);
    let data_key = state.kms.generate_data_key().await?;
    let nonce = generate_nonce();
    let ciphertext = seal(&data_key.plaintext, &nonce, &aad, plaintext)?;
    Ok(Sealed {
        key_id: data_key.key_id,
        wrapped_dek: data_key.wrapped,
        nonce: nonce.to_vec(),
        ciphertext,
        aad,
    })
}

async fn open_version(
    state: &AppState,
    key_id: &str,
    wrapped: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> ApiResult<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow!("stored nonce has invalid length")))?;
    let dek: Dek = state.kms.decrypt_data_key(wrapped, key_id).await?;
    Ok(open(&dek, &nonce, aad, ciphertext)?)
}

async fn insert_version(
    tx: &tokio_postgres::Transaction<'_>,
    secret_id: &str,
    version: i32,
    sealed: &Sealed,
) -> ApiResult<()> {
    tx.execute(
        "INSERT INTO vault.secret_versions \
            (secret_id, version, kms_key_id, wrapped_dek, nonce, ciphertext, aad) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)",
        &[
            &secret_id,
            &version,
            &sealed.key_id,
            &sealed.wrapped_dek,
            &sealed.nonce,
            &sealed.ciphertext,
            &sealed.aad,
        ],
    )
    .await?;
    Ok(())
}

async fn load_metadata(state: &AppState, name: &str) -> ApiResult<SecretMetadata> {
    let client = state.db.reader().await?;
    let row = client
        .query_opt(
            "SELECT name, kind::text, description, current_version, \
                EXTRACT(EPOCH FROM rotation_interval)::bigint, \
                EXTRACT(EPOCH FROM grace_period)::bigint, \
                next_rotation_at::text, created_at::text, updated_at::text \
             FROM vault.secrets WHERE name = $1",
            &[&name],
        )
        .await?
        .ok_or(ApiError::NotFound)?;

    Ok(SecretMetadata {
        name: row.get(0),
        kind: parse_kind(row.get::<_, String>(1))?,
        description: row.get(2),
        version: row.get(3),
        rotation_interval_secs: row.get(4),
        grace_period_secs: row.get::<_, Option<i64>>(5).unwrap_or(0),
        next_rotation_at: row.get(6),
        created_at: row.get(7),
        updated_at: row.get(8),
    })
}

async fn audit(
    state: &AppState,
    actor: Option<&str>,
    client_ip: Option<Ipv4Addr>,
    action: &str,
    secret_name: Option<&str>,
    outcome: &str,
) {
    let Ok(writer) = state.db.writer().await else {
        tracing::warn!(action, "audit log skipped: no writer connection");
        return;
    };
    let ip_text = client_ip.map(|ip| ip.to_string());
    let _ = writer
        .execute(
            "INSERT INTO vault.audit_log (actor, client_ip, action, secret_name, outcome) \
             VALUES ($1, $2::inet, $3, $4, $5)",
            &[&actor, &ip_text, &action, &secret_name, &outcome],
        )
        .await;
}

fn parse_kind(value: String) -> ApiResult<SecretKind> {
    SecretKind::parse(&value)
        .ok_or_else(|| ApiError::Internal(anyhow!("unknown secret kind '{value}' in database")))
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

fn normalize_grace(grace: Option<i64>) -> ApiResult<i64> {
    match grace {
        None => Ok(0),
        Some(secs) if secs >= 0 => Ok(secs),
        Some(_) => Err(ApiError::BadRequest(
            "grace_period_secs must not be negative".into(),
        )),
    }
}

fn insert_conflict(err: tokio_postgres::Error, name: &str) -> ApiError {
    if let Some(db_err) = err.as_db_error() {
        if db_err.code() == &SqlState::UNIQUE_VIOLATION {
            return ApiError::Conflict(format!("secret '{name}' already exists"));
        }
    }
    ApiError::Internal(anyhow::Error::new(err))
}

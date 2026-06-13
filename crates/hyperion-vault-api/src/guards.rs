use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::lockout;
use crate::state::SharedState;

pub struct AdminActor {
    pub name: String,
    pub is_admin: bool,
    pub rules: Vec<(String, String)>,
    pub client_ip: Option<IpAddr>,
}

impl FromRequestParts<SharedState> for AdminActor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip(parts, state.trust_proxy);
        lockout::check(state, ip).await?;

        let token = match bearer_token(parts) {
            Some(token) => token,
            None => {
                lockout::record(state, ip).await;
                return Err(ApiError::Unauthorized);
            }
        };
        let fingerprint = hyperion_vault_core::auth::fingerprint(&token).to_vec();

        let client = state.db.reader().await?;
        let row = client
            .query_opt(
                "SELECT t.name, COALESCE(r.is_admin, false), t.role_id::text \
                 FROM vault.admin_tokens t \
                 LEFT JOIN vault.roles r ON r.id = t.role_id \
                 WHERE t.token_sha256 = $1 AND t.revoked_at IS NULL",
                &[&fingerprint],
            )
            .await?;

        let (name, is_admin, role_id): (String, bool, Option<String>) = match row {
            Some(row) => (row.get(0), row.get(1), row.get(2)),
            None => {
                lockout::record(state, ip).await;
                return Err(ApiError::Unauthorized);
            }
        };

        let rules = match &role_id {
            Some(role_id) => {
                let rows = client
                    .query(
                        "SELECT action, path_pattern FROM vault.role_permissions WHERE role_id = $1::uuid",
                        &[role_id],
                    )
                    .await?;
                rows.iter()
                    .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                    .collect()
            }
            None => Vec::new(),
        };

        if let Ok(writer) = state.db.writer().await {
            let _ = writer
                .execute(
                    "UPDATE vault.admin_tokens SET last_used_at = now() WHERE token_sha256 = $1",
                    &[&fingerprint],
                )
                .await;
        }

        Ok(AdminActor {
            name,
            is_admin,
            rules,
            client_ip: ip,
        })
    }
}

pub struct ReaderGuard {
    pub client_ip: Ipv4Addr,
}

impl FromRequestParts<SharedState> for ReaderGuard {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip(parts, state.trust_proxy).ok_or(ApiError::Forbidden)?;
        lockout::check_ip(state, ip).await?;
        match ip {
            IpAddr::V4(v4) if state.allowlist.contains(v4) => Ok(ReaderGuard { client_ip: v4 }),
            _ => {
                lockout::record(state, Some(ip)).await;
                Err(ApiError::Forbidden)
            }
        }
    }
}

fn bearer_token(parts: &Parts) -> Option<String> {
    let header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn client_ip(parts: &Parts, trust_proxy: bool) -> Option<IpAddr> {
    if trust_proxy {
        if let Some(value) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|header| header.to_str().ok())
        {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

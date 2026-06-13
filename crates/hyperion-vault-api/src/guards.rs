use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::state::SharedState;

pub struct AdminActor(pub String);

impl FromRequestParts<SharedState> for AdminActor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let fingerprint = hyperion_vault_core::auth::fingerprint(&token).to_vec();

        let client = state.db.reader().await?;
        let row = client
            .query_opt(
                "SELECT name FROM vault.admin_tokens WHERE token_sha256 = $1 AND revoked_at IS NULL",
                &[&fingerprint],
            )
            .await?;

        let name: String = match row {
            Some(row) => row.get(0),
            None => return Err(ApiError::Unauthorized),
        };

        if let Ok(writer) = state.db.writer().await {
            let _ = writer
                .execute(
                    "UPDATE vault.admin_tokens SET last_used_at = now() WHERE token_sha256 = $1",
                    &[&fingerprint],
                )
                .await;
        }

        Ok(AdminActor(name))
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
        match ip {
            IpAddr::V4(v4) if state.allowlist.contains(v4) => Ok(ReaderGuard { client_ip: v4 }),
            _ => Err(ApiError::Forbidden),
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

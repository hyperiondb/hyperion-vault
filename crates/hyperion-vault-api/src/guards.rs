use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::clock::now_unix;
use crate::error::ApiError;
use crate::lockout;
use crate::state::SharedState;
use crate::store::Command;

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

        let record = state
            .store
            .token_by_fingerprint(fingerprint.clone())
            .await?;
        let token_record = match record {
            Some(record) if record.revoked_at.is_none() => record,
            _ => {
                lockout::record(state, ip).await;
                return Err(ApiError::Unauthorized);
            }
        };

        let (is_admin, rules) = match &token_record.role {
            Some(role_name) => match state.store.role(role_name.clone()).await? {
                Some(role) => (role.is_admin, role.permissions.clone()),
                None => (false, Vec::new()),
            },
            None => (false, Vec::new()),
        };

        let _ = state
            .store
            .apply(Command::TouchToken {
                fingerprint,
                at: now_unix(),
            })
            .await;

        Ok(AdminActor {
            name: token_record.name,
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

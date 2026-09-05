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
    pub peer_ip: Option<IpAddr>,
}

impl FromRequestParts<SharedState> for AdminActor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip(parts, state.trust_proxy);
        let peer = peer_ip(parts);
        lockout::check(state, peer).await?;

        let token = match bearer_token(parts) {
            Some(token) => token,
            None => {
                lockout::record(state, peer).await;
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
                lockout::record(state, peer).await;
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

        // On a cluster this is a replicated write, so it is written at most
        // once per token per VAULT_TOKEN_TOUCH_SECS instead of once per request.
        let now = now_unix();
        let due = match token_record.last_used_at {
            None => true,
            Some(at) => now.saturating_sub(at) >= state.token_touch_secs,
        };
        if due {
            let _ = state
                .store
                .apply(Command::TouchToken {
                    fingerprint,
                    at: now,
                })
                .await;
        }

        Ok(AdminActor {
            name: token_record.name,
            is_admin,
            rules,
            client_ip: ip,
            peer_ip: peer,
        })
    }
}

pub struct ReaderGuard {
    pub client_ip: Ipv4Addr,
    pub peer_ip: IpAddr,
}

impl FromRequestParts<SharedState> for ReaderGuard {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let peer = peer_ip(parts).ok_or(ApiError::Forbidden)?;
        let ip = client_ip(parts, state.trust_proxy).ok_or(ApiError::Forbidden)?;
        lockout::check_ip(state, peer).await?;
        match ip {
            IpAddr::V4(v4) if state.allowlist.contains(v4) => Ok(ReaderGuard {
                client_ip: v4,
                peer_ip: peer,
            }),
            _ => {
                tracing::warn!(client_ip = %ip, peer_ip = %peer, "read denied: client IP not in VAULT_ALLOWED_IPS");
                lockout::record(state, Some(peer)).await;
                Err(ApiError::Forbidden)
            }
        }
    }
}

pub fn bearer_token(parts: &Parts) -> Option<String> {
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

// The address of the TCP connection itself. A client cannot forge it, so it is
// what every lockout counter is keyed on, while `client_ip` below is the address
// the request claims to come from and is what the read allowlist and the audit
// log use.
pub fn peer_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

pub fn client_ip(parts: &Parts, trust_proxy: bool) -> Option<IpAddr> {
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

    peer_ip(parts)
}

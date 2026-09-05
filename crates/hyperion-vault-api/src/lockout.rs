use std::net::IpAddr;

use crate::clock::now_unix;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::store::Command;

pub async fn check(state: &AppState, ip: Option<IpAddr>) -> ApiResult<()> {
    if state.auth_max_failures == 0 {
        return Ok(());
    }
    match ip {
        Some(ip) => check_ip(state, ip).await,
        None => Ok(()),
    }
}

pub async fn check_ip(state: &AppState, ip: IpAddr) -> ApiResult<()> {
    check_key(state, ip.to_string()).await
}

pub async fn record(state: &AppState, ip: Option<IpAddr>) {
    let Some(ip) = ip else {
        return;
    };
    record_key(state, ip.to_string()).await;
}

// A wrong value presented to /verify is produced by whoever is talking to the
// calling service, not by the caller itself, so it is counted per (client ip,
// secret) and gates only /verify. Secret reads and token auth keep the counter
// above.
pub async fn check_verify(state: &AppState, peer: IpAddr, secret: &str) -> ApiResult<()> {
    check_key(state, verify_key(peer, secret)).await
}

pub async fn record_verify(state: &AppState, peer: IpAddr, secret: &str) {
    record_key(state, verify_key(peer, secret)).await;
}

pub fn verify_key(peer: IpAddr, secret: &str) -> String {
    format!("verify:{peer}:{secret}")
}

async fn check_key(state: &AppState, key: String) -> ApiResult<()> {
    if state.auth_max_failures == 0 {
        return Ok(());
    }
    if let Some(record) = state.store.lockout(key).await? {
        if let Some(until) = record.locked_until {
            if until > now_unix() {
                return Err(ApiError::TooManyRequests);
            }
        }
    }
    Ok(())
}

async fn record_key(state: &AppState, key: String) {
    if state.auth_max_failures == 0 {
        return;
    }
    let command = Command::RecordAuthFailure {
        key,
        now: now_unix(),
        max: state.auth_max_failures,
        window_secs: state.auth_window_secs,
        lockout_secs: state.auth_lockout_secs,
    };
    if let Err(err) = state.store.apply(command).await {
        tracing::warn!(error = %err, "failed to record auth failure");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verify_key_cannot_collide_with_a_plain_ip_key() {
        let ip = IpAddr::from([10, 0, 0, 5]);
        let key = verify_key(ip, "db/password");
        assert_eq!(key, "verify:10.0.0.5:db/password");
        assert_ne!(key, ip.to_string());
    }
}

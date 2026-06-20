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
    if state.auth_max_failures == 0 {
        return Ok(());
    }
    if let Some(record) = state.store.lockout(ip.to_string()).await? {
        if let Some(until) = record.locked_until {
            if until > now_unix() {
                return Err(ApiError::TooManyRequests);
            }
        }
    }
    Ok(())
}

pub async fn record(state: &AppState, ip: Option<IpAddr>) {
    if state.auth_max_failures == 0 {
        return;
    }
    let Some(ip) = ip else {
        return;
    };
    let command = Command::RecordAuthFailure {
        ip: ip.to_string(),
        now: now_unix(),
        max: state.auth_max_failures,
        window_secs: state.auth_window_secs,
        lockout_secs: state.auth_lockout_secs,
    };
    if let Err(err) = state.store.apply(command).await {
        tracing::warn!(error = %err, "failed to record auth failure");
    }
}

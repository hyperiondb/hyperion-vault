use std::net::IpAddr;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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
    let client = state.db.reader().await?;
    let ip_text = ip.to_string();
    let row = client
        .query_opt(
            "SELECT 1 FROM vault.auth_lockouts \
             WHERE client_ip = $1::inet AND locked_until IS NOT NULL AND locked_until > now()",
            &[&ip_text],
        )
        .await?;
    if row.is_some() {
        Err(ApiError::TooManyRequests)
    } else {
        Ok(())
    }
}

pub async fn record(state: &AppState, ip: Option<IpAddr>) {
    if state.auth_max_failures == 0 {
        return;
    }
    let Some(ip) = ip else {
        return;
    };
    let Ok(writer) = state.db.writer().await else {
        tracing::warn!("auth-failure not recorded: no writer connection");
        return;
    };
    let ip_text = ip.to_string();
    let max = state.auth_max_failures as i32;
    let window = state.auth_window_secs;
    let lockout = state.auth_lockout_secs;
    if let Err(err) = writer
        .execute(
            "SELECT vault.record_auth_failure($1::inet, $2, $3, $4)",
            &[&ip_text, &max, &window, &lockout],
        )
        .await
    {
        tracing::warn!(error = %err, "failed to record auth failure");
    }
}

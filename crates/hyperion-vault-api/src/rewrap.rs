use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::clock::{now_unix, rfc3339};
use crate::dto::{RewrapRunResponse, RewrapStatusResponse};
use crate::state::AppState;
use crate::store::{Command, KmsRewrapState, VersionRecord};

#[derive(Debug, Default, Clone, Copy)]
pub struct RewrapSummary {
    pub scanned: usize,
    pub rewrapped: usize,
    pub failed: usize,
}

fn needs_rewrap(version: &VersionRecord, target: i64) -> bool {
    version
        .wrapped_rotation_at
        .is_none_or(|current| current < target)
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub async fn target_rotation(state: &AppState) -> Result<Option<i64>> {
    state.kms.latest_rotation_at().await
}

pub async fn run_pass(state: &AppState, target: i64) -> Result<RewrapSummary> {
    if state.rewrap_busy.swap(true, Ordering::SeqCst) {
        return Err(anyhow!("a re-wrap pass is already running on this node"));
    }
    let _guard = BusyGuard(&state.rewrap_busy);

    let now = now_unix();
    let secrets = state.store.list_secrets().await?;
    let mut summary = RewrapSummary::default();

    for secret in secrets {
        let versions = state.store.live_versions(secret.name.clone(), now).await?;
        for version in versions {
            summary.scanned += 1;
            if !needs_rewrap(&version, target) {
                continue;
            }
            match rewrap_one(state, &secret.name, &version, target).await {
                Ok(()) => summary.rewrapped += 1,
                Err(err) => {
                    summary.failed += 1;
                    tracing::warn!(
                        secret = %secret.name,
                        version = version.version,
                        error = %err,
                        "kms re-wrap failed for version; leaving it under its current key"
                    );
                }
            }
            pace(state).await;
        }
    }
    Ok(summary)
}

async fn rewrap_one(
    state: &AppState,
    name: &str,
    version: &VersionRecord,
    target: i64,
) -> Result<()> {
    let version_str = version.version.to_string();
    let context = [("secret", name), ("version", version_str.as_str())];
    let (wrapped_dek, kms_key_id) = state
        .kms
        .reencrypt_data_key(&version.wrapped_dek, &version.kms_key_id, &context)
        .await?;
    state
        .store
        .apply(Command::RewrapVersion {
            name: name.to_string(),
            version: version.version,
            kms_key_id,
            wrapped_dek,
            wrapped_rotation_at: target,
        })
        .await?;
    Ok(())
}

async fn pace(state: &AppState) {
    let rate = state.kms_rewrap_max_per_sec;
    if rate > 0 {
        tokio::time::sleep(Duration::from_millis(1000 / rate as u64)).await;
    }
}

pub async fn persist_completed(state: &AppState, target: i64) -> Result<()> {
    let now = now_unix();
    let record = KmsRewrapState {
        last_completed_rotation_at: target,
        last_swept_at: now,
        updated_at: now,
    };
    state
        .store
        .apply(Command::SetKmsRewrapState { state: record })
        .await?;
    Ok(())
}

pub async fn force(state: &AppState) -> Result<RewrapRunResponse> {
    let target = target_rotation(state).await?.unwrap_or(0);
    let summary = run_pass(state, target).await?;
    if summary.failed == 0 && target > 0 {
        persist_completed(state, target).await?;
    }
    Ok(RewrapRunResponse {
        scanned: summary.scanned,
        rewrapped: summary.rewrapped,
        failed: summary.failed,
        target_rotation_at: (target > 0).then(|| rfc3339(target)),
    })
}

pub async fn status(state: &AppState) -> Result<RewrapStatusResponse> {
    let persisted = state.store.kms_rewrap_state().await?;
    let latest = target_rotation(state).await.ok().flatten();
    let last_completed = persisted
        .as_ref()
        .map(|s| s.last_completed_rotation_at)
        .unwrap_or(0);
    let target = latest.unwrap_or(last_completed);

    let now = now_unix();
    let mut total = 0usize;
    let mut pending = 0usize;
    for secret in state.store.list_secrets().await? {
        for version in state.store.live_versions(secret.name.clone(), now).await? {
            total += 1;
            if needs_rewrap(&version, target) {
                pending += 1;
            }
        }
    }

    Ok(RewrapStatusResponse {
        enabled: state.kms_rewrap_enabled,
        busy: state.rewrap_busy.load(Ordering::SeqCst),
        last_completed_rotation_at: (last_completed > 0).then(|| rfc3339(last_completed)),
        latest_rotation_at: latest.map(rfc3339),
        total_versions: total,
        pending_versions: pending,
    })
}

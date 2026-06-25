use std::time::Duration;

use anyhow::Result;

use crate::rewrap;
use crate::state::SharedState;

pub async fn run(state: SharedState, poll_secs: u64) {
    let period = Duration::from_secs(poll_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(poll_secs, "kms rewrap worker started");

    loop {
        ticker.tick().await;
        if let Err(err) = tick(&state).await {
            tracing::warn!(error = %err, "kms rewrap worker tick failed");
        }
    }
}

async fn tick(state: &SharedState) -> Result<()> {
    if !is_leader(state).await {
        return Ok(());
    }

    let latest = rewrap::target_rotation(state).await?;

    let persisted = state.store.kms_rewrap_state().await?;
    let Some(persisted) = persisted else {
        let baseline = latest.unwrap_or(0);
        rewrap::persist_completed(state, baseline).await?;
        tracing::info!(baseline, "seeded kms rewrap watermark (no initial sweep)");
        return Ok(());
    };

    let target = match latest {
        Some(target) => target,
        None => return Ok(()),
    };

    if target <= persisted.last_completed_rotation_at {
        return Ok(());
    }

    tracing::info!(
        from = persisted.last_completed_rotation_at,
        to = target,
        "kms key rotation detected; re-wrapping live secret versions onto new key material"
    );
    let summary = rewrap::run_pass(state, target).await?;
    if summary.failed == 0 {
        rewrap::persist_completed(state, target).await?;
        tracing::info!(
            scanned = summary.scanned,
            rewrapped = summary.rewrapped,
            target,
            "kms rewrap pass complete"
        );
    } else {
        tracing::warn!(
            scanned = summary.scanned,
            rewrapped = summary.rewrapped,
            failed = summary.failed,
            "kms rewrap pass had failures; watermark not advanced, will retry next tick"
        );
    }
    Ok(())
}

async fn is_leader(state: &SharedState) -> bool {
    match &state.raft {
        None => true,
        Some(raft) => raft.current_leader().await == Some(state.node_id),
    }
}

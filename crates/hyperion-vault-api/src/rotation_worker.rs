use std::time::Duration;

use anyhow::Result;

use crate::clock::now_unix;
use crate::service;
use crate::state::SharedState;
use crate::store::Command;

pub async fn run(state: SharedState, poll_secs: u64) {
    let period = Duration::from_secs(poll_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(poll_secs, "rotation worker started");

    loop {
        ticker.tick().await;
        if let Err(err) = tick(&state).await {
            tracing::warn!(error = %err, "rotation worker tick failed");
        }
    }
}

async fn tick(state: &SharedState) -> Result<()> {
    if !is_leader(state).await {
        return Ok(());
    }

    state
        .store
        .apply(Command::ExpireGraceVersions { now: now_unix() })
        .await?;

    let due = state.store.due_rotations(now_unix()).await?;
    if due.is_empty() {
        return Ok(());
    }
    tracing::info!(count = due.len(), "rotating due secrets");

    for secret in due {
        match service::rotate(state, "rotation-worker", None, &secret.name).await {
            Ok(value) => {
                tracing::info!(secret = %secret.name, version = value.version, "rotated secret")
            }
            Err(err) => tracing::warn!(secret = %secret.name, error = ?err, "rotation failed"),
        }
    }

    Ok(())
}

async fn is_leader(state: &SharedState) -> bool {
    match &state.raft {
        None => true,
        Some(raft) => raft.current_leader().await == Some(state.node_id),
    }
}

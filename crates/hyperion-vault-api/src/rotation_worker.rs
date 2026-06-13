use std::time::Duration;

use anyhow::Result;

use crate::service;
use crate::state::SharedState;

const CLAIM_SQL: &str = "UPDATE vault.rotation_jobs \
     SET claimed_at = now(), claimed_by = $1 \
     WHERE id IN ( \
         SELECT id FROM vault.rotation_jobs \
         WHERE completed_at IS NULL \
           AND (claimed_at IS NULL OR claimed_at < now() - interval '5 minutes') \
         ORDER BY id \
         FOR UPDATE SKIP LOCKED \
         LIMIT 10) \
     RETURNING id, secret_id::text";

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
    let claimed: Vec<(i64, String)> = {
        let client = state.db.writer().await?;
        let rows = client.query(CLAIM_SQL, &[&state.node_name]).await?;
        rows.iter()
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
            .collect()
    };

    if claimed.is_empty() {
        return Ok(());
    }
    tracing::info!(count = claimed.len(), "claimed rotation jobs");

    for (job_id, secret_id) in claimed {
        match lookup_name(state, &secret_id).await? {
            Some(name) => match service::rotate(state, &state.node_name, None, &name).await {
                Ok(value) => {
                    complete_job(state, job_id, None).await?;
                    tracing::info!(secret = %name, version = value.version, "rotated secret");
                }
                Err(err) => {
                    complete_job(state, job_id, Some(format!("{err:?}"))).await?;
                    tracing::warn!(secret = %name, "rotation failed");
                }
            },
            None => complete_job(state, job_id, Some("secret no longer exists".into())).await?,
        }
    }

    Ok(())
}

async fn lookup_name(state: &SharedState, secret_id: &str) -> Result<Option<String>> {
    let client = state.db.reader().await?;
    let row = client
        .query_opt(
            "SELECT name FROM vault.secrets WHERE id = $1::uuid",
            &[&secret_id],
        )
        .await?;
    Ok(row.map(|row| row.get(0)))
}

async fn complete_job(state: &SharedState, job_id: i64, error: Option<String>) -> Result<()> {
    let client = state.db.writer().await?;
    client
        .execute(
            "UPDATE vault.rotation_jobs SET completed_at = now(), error = $2 WHERE id = $1",
            &[&job_id, &error],
        )
        .await?;
    Ok(())
}

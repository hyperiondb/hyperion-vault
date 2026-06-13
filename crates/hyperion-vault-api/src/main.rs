mod config;
mod db;
mod dto;
mod error;
mod guards;
mod kms;
mod rotation_worker;
mod routes;
mod service;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Db;
use crate::state::{AppState, SharedState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;

    let allowlist = hyperion_vault_core::IpAllowlist::parse(&cfg.allowed_ips)
        .context("VAULT_ALLOWED_IPS is invalid")?;
    if allowlist.is_empty() {
        tracing::warn!("VAULT_ALLOWED_IPS is empty: all secret reads will be denied (fail-closed)");
    } else {
        tracing::info!(entries = allowlist.len(), "read IP allowlist loaded");
    }

    let db = Db::connect(&cfg)?;
    let kms = kms::build(&cfg).await?;

    let state: SharedState = Arc::new(AppState {
        db,
        kms,
        allowlist,
        trust_proxy: cfg.trust_proxy,
        node_name: cfg.node_name.clone(),
    });

    let worker_state = state.clone();
    let poll = cfg.rotation_poll_secs;
    tokio::spawn(async move { rotation_worker::run(worker_state, poll).await });

    let listen = cfg.listen;
    let app = routes::router(state);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    tracing::info!(%listen, "hyperion-vault-api listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;

    Ok(())
}

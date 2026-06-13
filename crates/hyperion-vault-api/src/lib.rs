pub mod authz;
pub mod cache;
pub mod config;
pub mod db;
pub mod dto;
pub mod error;
pub mod guards;
pub mod kms;
pub mod lockout;
pub mod manage;
pub mod rotation_worker;
pub mod routes;
pub mod service;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Db;
use crate::state::{AppState, SharedState};

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

pub async fn build_state(cfg: &Config) -> anyhow::Result<SharedState> {
    let allowlist = hyperion_vault_core::IpAllowlist::parse(&cfg.allowed_ips)
        .context("VAULT_ALLOWED_IPS is invalid")?;
    if allowlist.is_empty() {
        tracing::warn!("VAULT_ALLOWED_IPS is empty: all secret reads will be denied (fail-closed)");
    } else {
        tracing::info!(entries = allowlist.len(), "read IP allowlist loaded");
    }

    let db = Db::connect(cfg)?;
    let kms = kms::build(cfg).await?;
    let dek_cache = cache::DekCache::new(cfg.dek_cache_ttl_secs);
    if dek_cache.enabled() {
        tracing::info!(
            ttl_secs = cfg.dek_cache_ttl_secs,
            "decrypted-DEK cache enabled (KMS-outage resilient reads)"
        );
    } else {
        tracing::warn!(
            "decrypted-DEK cache disabled: every read calls KMS and reads fail during a KMS outage"
        );
    }

    if cfg.auth_max_failures > 0 {
        tracing::info!(
            max_failures = cfg.auth_max_failures,
            lockout_secs = cfg.auth_lockout_secs,
            window_secs = cfg.auth_window_secs,
            "auth lockout enabled (cluster-wide)"
        );
    } else {
        tracing::warn!("auth lockout disabled (VAULT_AUTH_MAX_FAILURES=0)");
    }

    Ok(Arc::new(AppState {
        db,
        kms,
        dek_cache,
        allowlist,
        trust_proxy: cfg.trust_proxy,
        node_name: cfg.node_name.clone(),
        auth_max_failures: cfg.auth_max_failures,
        auth_lockout_secs: cfg.auth_lockout_secs,
        auth_window_secs: cfg.auth_window_secs,
    }))
}

pub async fn serve() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    let state = build_state(&cfg).await?;

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

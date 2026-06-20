#![allow(clippy::result_large_err)]

pub mod authz;
pub mod cache;
pub mod clock;
pub mod config;
pub mod dto;
pub mod error;
pub mod guards;
pub mod kms;
pub mod lockout;
pub mod manage;
pub mod raft;
pub mod rotation_worker;
pub mod routes;
pub mod service;
pub mod state;
pub mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::raft::{RaftNode, RaftStore};
use crate::state::{AppState, SharedState};
use crate::store::{
    Command, RedbStore, StoreError, TokenRecord, VaultReader, VaultStore, VaultWriter,
};

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

    let redb = RedbStore::open(&cfg.db_path, cfg.node_id).context("open redb store")?;
    tracing::info!(path = %cfg.db_path, node_id = cfg.node_id, "redb store opened");

    if let Some(token) = &cfg.bootstrap_token {
        let fingerprint = hyperion_vault_core::auth::fingerprint(token).to_vec();
        if redb
            .token_by_fingerprint(fingerprint.clone())
            .await?
            .is_none()
        {
            let record = TokenRecord {
                name: "bootstrap-admin".to_string(),
                role: Some("admin".to_string()),
                fingerprint,
                created_at: crate::clock::now_unix(),
                last_used_at: None,
                revoked_at: None,
            };
            match redb.apply(Command::AddToken { token: record }).await {
                Ok(()) => tracing::warn!(
                    "seeded 'bootstrap-admin' token from VAULT_BOOTSTRAP_TOKEN (rotate it after first use)"
                ),
                Err(StoreError::Conflict(_)) => {}
                Err(err) => return Err(err.into()),
            }
        }
    }

    let store: Arc<dyn VaultStore>;
    let raft: Option<crate::raft::Raft>;

    if cfg.peers.len() > 1 {
        let node = RaftNode::start(redb.clone(), cfg.node_id, cfg.peers.clone())
            .await
            .context("failed to start raft node")?;
        node.bootstrap().await.context("raft bootstrap failed")?;

        let handle = node.raft.clone();
        let raft_listen = raft_listen_addr(cfg)?;
        let server_handle = handle.clone();
        tokio::spawn(async move {
            if let Err(err) = raft::server::serve(server_handle, raft_listen).await {
                tracing::error!(error = %err, "raft RPC server stopped");
            }
        });
        tracing::info!(peers = cfg.peers.len(), "raft replication enabled");

        store = Arc::new(RaftStore::new(node));
        raft = Some(handle);
    } else {
        tracing::info!("single-node mode (VAULT_PEERS lists one node or none): raft disabled");
        store = redb;
        raft = None;
    }

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
            "auth lockout enabled (per-node)"
        );
    } else {
        tracing::warn!("auth lockout disabled (VAULT_AUTH_MAX_FAILURES=0)");
    }

    Ok(Arc::new(AppState {
        store,
        kms,
        dek_cache,
        allowlist,
        trust_proxy: cfg.trust_proxy,
        node_id: cfg.node_id,
        raft,
        auth_max_failures: cfg.auth_max_failures,
        auth_lockout_secs: cfg.auth_lockout_secs,
        auth_window_secs: cfg.auth_window_secs,
    }))
}

fn raft_listen_addr(cfg: &Config) -> anyhow::Result<SocketAddr> {
    let addr = cfg
        .self_addr()
        .with_context(|| format!("NODE_ID {} is not present in VAULT_PEERS", cfg.node_id))?;
    let port: u16 = addr
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("VAULT_PEERS address '{addr}' must be host:port"))?;
    format!("0.0.0.0:{port}")
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid raft listen port {port}"))
}

pub async fn serve() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    if cfg.peers.len() > 1 && cfg.self_addr().is_none() {
        bail!("NODE_ID {} is not present in VAULT_PEERS", cfg.node_id);
    }

    let state = build_state(&cfg).await?;

    let worker_state = state.clone();
    let poll = cfg.rotation_poll_secs;
    tokio::spawn(async move { rotation_worker::run(worker_state, poll).await });

    let listen = cfg.api_listen;
    let app = routes::router(state);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    tracing::info!(%listen, node_id = cfg.node_id, "hyperion-vault-api listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;

    Ok(())
}

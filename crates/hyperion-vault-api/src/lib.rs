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
pub mod pg_apply;
pub mod raft;
pub mod rewrap;
pub mod rewrap_worker;
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

    let pg_targets = build_pg_target_policy(cfg, &redb).await?;

    let store: Arc<dyn VaultStore>;
    let raft: Option<crate::raft::Raft>;

    if cfg.peers.len() > 1 {
        let auth = Arc::new(
            raft::PeerAuth::new(cfg.cluster_token.clone(), cfg.cluster_auth_required)
                .context("VAULT_CLUSTER_TOKEN / VAULT_CLUSTER_AUTH_REQUIRED are invalid")?,
        );
        let peers = raft::PeerAddrs::new(cfg.raft_peer_check, &cfg.peers).await;
        log_peer_guard(&auth, &peers).await;

        let node = RaftNode::start(redb.clone(), cfg.node_id, cfg.peers.clone(), auth.clone())
            .await
            .context("failed to start raft node")?;

        let handle = node.raft.clone();
        let raft_listen = raft_listen_addr(cfg)?;
        let server_state = raft::server::ServerState {
            raft: handle.clone(),
            auth,
            peers,
        };
        tokio::spawn(async move {
            if let Err(err) = raft::server::serve(server_state, raft_listen).await {
                tracing::error!(error = %err, "raft RPC server stopped");
            }
        });

        node.bootstrap().await.context("raft bootstrap failed")?;
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
        pg_targets,
        node_id: cfg.node_id,
        raft,
        auth_max_failures: cfg.auth_max_failures,
        auth_lockout_secs: cfg.auth_lockout_secs,
        auth_window_secs: cfg.auth_window_secs,
        token_touch_secs: cfg.token_touch_secs,
        kms_rewrap_enabled: cfg.kms_rewrap_enabled,
        kms_rewrap_max_per_sec: cfg.kms_rewrap_max_per_sec,
        rewrap_busy: std::sync::atomic::AtomicBool::new(false),
    }))
}

async fn build_pg_target_policy(
    cfg: &Config,
    redb: &Arc<RedbStore>,
) -> anyhow::Result<pg_apply::PgTargetPolicy> {
    let ca_file = cfg.pg_target_ca_file.as_deref();

    if !cfg.pg_target_hosts.trim().is_empty() {
        let policy =
            pg_apply::PgTargetPolicy::build(&cfg.pg_target_hosts, cfg.pg_target_tls, ca_file)
                .context(
                "VAULT_PG_TARGET_HOSTS / VAULT_PG_TARGET_TLS / VAULT_PG_TARGET_CA_FILE are invalid",
            )?;
        log_pg_target_policy(&policy, false);
        return Ok(policy);
    }

    let stored: Vec<String> = redb
        .list_secrets()
        .await?
        .into_iter()
        .filter_map(|secret| secret.target)
        .flat_map(|target| match target {
            crate::store::RotationTarget::PgReplica(pg) => pg.hosts,
        })
        .collect();

    let policy = pg_apply::PgTargetPolicy::seeded(stored, cfg.pg_target_tls, ca_file)
        .context("VAULT_PG_TARGET_TLS / VAULT_PG_TARGET_CA_FILE are invalid")?;
    log_pg_target_policy(&policy, true);
    Ok(policy)
}

fn log_pg_target_policy(policy: &pg_apply::PgTargetPolicy, seeded: bool) {
    if policy.is_empty() {
        tracing::info!(
            "VAULT_PG_TARGET_HOSTS is empty and no stored secret carries a pg_replica target: such targets are refused"
        );
        return;
    }

    if seeded {
        tracing::warn!(
            hosts = ?policy.hosts(),
            "VAULT_PG_TARGET_HOSTS is not set: allowing only the Postgres hosts already used by stored rotation targets; set VAULT_PG_TARGET_HOSTS explicitly"
        );
    } else {
        tracing::info!(hosts = ?policy.hosts(), "pg_replica rotation target allowlist loaded");
    }

    if policy.tls_required() {
        tracing::info!("pg_replica rotation connects with TLS and verifies the server certificate");
    } else if policy.tls_enabled() {
        tracing::warn!(
            "VAULT_PG_TARGET_TLS=prefer: rotation uses TLS only when the Postgres server offers it, otherwise it sends the login credential in plaintext; set VAULT_PG_TARGET_TLS=verify-full to require TLS"
        );
    } else {
        tracing::warn!(
            "VAULT_PG_TARGET_TLS=disable: rotation sends the login credential to Postgres targets in plaintext"
        );
    }
}

async fn log_peer_guard(auth: &raft::PeerAuth, peers: &Arc<raft::PeerAddrs>) {
    if auth.required() {
        tracing::info!("raft RPC requires the cluster credential (VAULT_CLUSTER_AUTH_REQUIRED)");
    } else if auth.configured() {
        tracing::warn!(
            "VAULT_CLUSTER_TOKEN is set but not required: peer requests carry it and requests without it are still accepted; set VAULT_CLUSTER_AUTH_REQUIRED=true once every node is rolled"
        );
    } else {
        tracing::warn!(
            "VAULT_CLUSTER_TOKEN is not set: the raft port accepts any request that reaches it"
        );
    }

    if peers.enabled() {
        tracing::info!(
            addresses = peers.resolved_len().await,
            "raft RPC accepts connections from configured peer addresses only"
        );
    } else {
        tracing::warn!(
            "VAULT_RAFT_PEER_CHECK is off: the raft port accepts connections from any source address"
        );
    }
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
    let bind = cfg.raft_bind.trim();
    format!("{bind}:{port}")
        .parse()
        .map_err(|_| anyhow::anyhow!("VAULT_RAFT_BIND '{bind}' with port {port} is not an address"))
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

    if cfg.kms_rewrap_enabled {
        let rewrap_state = state.clone();
        let rewrap_poll = cfg.kms_rewrap_poll_secs;
        tokio::spawn(async move { rewrap_worker::run(rewrap_state, rewrap_poll).await });
    } else {
        tracing::info!(
            "kms rewrap worker disabled (VAULT_KMS_REWRAP_ENABLED=false); manual /v1/admin/kms/rewrap still available"
        );
    }

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

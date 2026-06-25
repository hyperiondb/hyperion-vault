use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KmsMode {
    Aws,
    Local,
}

#[derive(Clone)]
pub struct Config {
    pub node_id: u64,
    pub peers: BTreeMap<u64, String>,
    pub api_listen: SocketAddr,
    pub db_path: String,
    pub bootstrap_token: Option<String>,
    pub allowed_ips: String,
    pub trust_proxy: bool,
    pub read_consistency_linearizable: bool,
    pub kms_mode: KmsMode,
    pub kms_key_id: String,
    pub local_master_key_b64: Option<String>,
    pub rotation_poll_secs: u64,
    pub dek_cache_ttl_secs: u64,
    pub kms_max_retries: u32,
    pub kms_rewrap_enabled: bool,
    pub kms_rewrap_poll_secs: u64,
    pub kms_rewrap_max_per_sec: u32,
    pub auth_max_failures: u32,
    pub auth_lockout_secs: i64,
    pub auth_window_secs: i64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let node_id: u64 = env_or("NODE_ID", "1")
            .parse()
            .context("NODE_ID must be a positive integer")?;
        if node_id == 0 {
            bail!("NODE_ID must be >= 1");
        }

        let peers = parse_peers(&env_or("VAULT_PEERS", ""))?;

        let api_port: u16 = env_or("VAULT_API_PORT", "8200")
            .parse()
            .context("VAULT_API_PORT must be a port number")?;
        let api_listen: SocketAddr = format!("0.0.0.0:{api_port}")
            .parse()
            .expect("0.0.0.0:<port> is a valid socket address");

        let db_path = env_or("VAULT_DB_PATH", "vault.redb");

        let kms_mode = match env_or("VAULT_KMS_MODE", "aws").to_lowercase().as_str() {
            "aws" => KmsMode::Aws,
            "local" => KmsMode::Local,
            other => bail!("VAULT_KMS_MODE must be 'aws' or 'local', got '{other}'"),
        };

        let kms_key_id = env_or("VAULT_KMS_KEY_ID", "");
        if kms_mode == KmsMode::Aws && kms_key_id.is_empty() {
            bail!("VAULT_KMS_KEY_ID is required when VAULT_KMS_MODE=aws");
        }

        let local_master_key_b64 = env_opt("VAULT_LOCAL_MASTER_KEY");
        if kms_mode == KmsMode::Local && local_master_key_b64.is_none() {
            tracing::warn!(
                "VAULT_KMS_MODE=local without VAULT_LOCAL_MASTER_KEY: a random master key is generated and lost on restart (DEV ONLY)"
            );
        }

        Ok(Self {
            node_id,
            peers,
            api_listen,
            db_path,
            bootstrap_token: env_opt("VAULT_BOOTSTRAP_TOKEN"),
            allowed_ips: env_or("VAULT_ALLOWED_IPS", ""),
            trust_proxy: parse_bool(&env_or("VAULT_TRUST_PROXY", "false")),
            read_consistency_linearizable: env_or("VAULT_READ_CONSISTENCY", "local").to_lowercase()
                == "linearizable",
            kms_mode,
            kms_key_id,
            local_master_key_b64,
            rotation_poll_secs: env_or("VAULT_ROTATION_POLL_SECS", "15")
                .parse()
                .context("VAULT_ROTATION_POLL_SECS must be an integer")?,
            dek_cache_ttl_secs: env_or("VAULT_DEK_CACHE_TTL_SECS", "300")
                .parse()
                .context("VAULT_DEK_CACHE_TTL_SECS must be an integer (seconds; 0 disables)")?,
            kms_max_retries: env_or("VAULT_KMS_MAX_RETRIES", "5")
                .parse()
                .context("VAULT_KMS_MAX_RETRIES must be an integer (0 disables retries)")?,
            kms_rewrap_enabled: parse_bool(&env_or("VAULT_KMS_REWRAP_ENABLED", "false")),
            kms_rewrap_poll_secs: env_or("VAULT_KMS_REWRAP_POLL_SECS", "86400")
                .parse()
                .context("VAULT_KMS_REWRAP_POLL_SECS must be an integer (seconds)")?,
            kms_rewrap_max_per_sec: env_or("VAULT_KMS_REWRAP_MAX_PER_SEC", "10")
                .parse()
                .context("VAULT_KMS_REWRAP_MAX_PER_SEC must be an integer (0 disables pacing)")?,
            auth_max_failures: env_or("VAULT_AUTH_MAX_FAILURES", "5")
                .parse()
                .context("VAULT_AUTH_MAX_FAILURES must be an integer (0 disables lockout)")?,
            auth_lockout_secs: env_or("VAULT_AUTH_LOCKOUT_SECS", "900")
                .parse()
                .context("VAULT_AUTH_LOCKOUT_SECS must be an integer (seconds a lockout lasts)")?,
            auth_window_secs: env_or("VAULT_AUTH_WINDOW_SECS", "300").parse().context(
                "VAULT_AUTH_WINDOW_SECS must be an integer (failure accumulation window)",
            )?,
        })
    }

    pub fn peer_addr(&self, id: u64) -> Option<&str> {
        self.peers.get(&id).map(|s| s.as_str())
    }

    pub fn self_addr(&self) -> Option<&str> {
        self.peer_addr(self.node_id)
    }
}

fn parse_peers(raw: &str) -> Result<BTreeMap<u64, String>> {
    let mut map = BTreeMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (id, addr) = entry
            .split_once('=')
            .with_context(|| format!("VAULT_PEERS entry '{entry}' must be 'id=host:port'"))?;
        let id: u64 = id
            .trim()
            .parse()
            .with_context(|| format!("VAULT_PEERS id '{id}' must be an integer"))?;
        let addr = addr.trim().to_string();
        if addr.is_empty() {
            bail!("VAULT_PEERS entry '{entry}' has an empty address");
        }
        map.insert(id, addr);
    }
    Ok(map)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn parse_bool(value: &str) -> bool {
    matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

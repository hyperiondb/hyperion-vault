use std::net::SocketAddr;

use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KmsMode {
    Aws,
    Local,
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub allowed_ips: String,
    pub trust_proxy: bool,
    pub pg_hosts: Vec<String>,
    pub pg_port: u16,
    pub pg_user: String,
    pub pg_password: String,
    pub pg_dbname: String,
    pub pool_max: usize,
    pub kms_mode: KmsMode,
    pub kms_key_id: String,
    pub local_master_key_b64: Option<String>,
    pub rotation_poll_secs: u64,
    pub dek_cache_ttl_secs: u64,
    pub kms_max_retries: u32,
    pub node_name: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen: SocketAddr = env_or("VAULT_API_LISTEN", "0.0.0.0:8200")
            .parse()
            .context("VAULT_API_LISTEN must be host:port")?;

        let pg_hosts: Vec<String> = env_or("VAULT_PG_HOSTS", "127.0.0.1")
            .split(',')
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty())
            .collect();
        if pg_hosts.is_empty() {
            bail!("VAULT_PG_HOSTS must list at least one host");
        }

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
            listen,
            allowed_ips: env_or("VAULT_ALLOWED_IPS", ""),
            trust_proxy: parse_bool(&env_or("VAULT_TRUST_PROXY", "false")),
            pg_hosts,
            pg_port: env_or("VAULT_PG_PORT", "5432")
                .parse()
                .context("VAULT_PG_PORT must be a port number")?,
            pg_user: env_or("VAULT_PG_USER", "vault_service"),
            pg_password: env_or("VAULT_PG_PASSWORD", ""),
            pg_dbname: env_or("VAULT_PG_DBNAME", "postgres"),
            pool_max: env_or("VAULT_PG_POOL_MAX", "16")
                .parse()
                .context("VAULT_PG_POOL_MAX must be an integer")?,
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
            node_name: env_or("VAULT_NODE_NAME", &hostname_fallback()),
        })
    }
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

fn hostname_fallback() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "vault-api".to_string())
}

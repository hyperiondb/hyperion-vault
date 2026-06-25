use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use hyperion_vault_core::IpAllowlist;

use crate::cache::DekCache;
use crate::kms::KmsProvider;
use crate::raft::Raft;
use crate::store::VaultStore;

pub struct AppState {
    pub store: Arc<dyn VaultStore>,
    pub kms: Arc<dyn KmsProvider>,
    pub dek_cache: DekCache,
    pub allowlist: IpAllowlist,
    pub trust_proxy: bool,
    pub node_id: u64,
    pub raft: Option<Raft>,
    pub auth_max_failures: u32,
    pub auth_lockout_secs: i64,
    pub auth_window_secs: i64,
    pub kms_rewrap_enabled: bool,
    pub kms_rewrap_max_per_sec: u32,
    pub rewrap_busy: AtomicBool,
}

pub type SharedState = Arc<AppState>;

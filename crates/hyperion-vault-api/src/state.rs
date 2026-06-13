use std::sync::Arc;

use hyperion_vault_core::IpAllowlist;

use crate::cache::DekCache;
use crate::db::Db;
use crate::kms::KmsProvider;

pub struct AppState {
    pub db: Db,
    pub kms: Arc<dyn KmsProvider>,
    pub dek_cache: DekCache,
    pub allowlist: IpAllowlist,
    pub trust_proxy: bool,
    pub node_name: String,
    pub auth_max_failures: u32,
    pub auth_lockout_secs: i64,
    pub auth_window_secs: i64,
}

pub type SharedState = Arc<AppState>;

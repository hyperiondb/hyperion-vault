use std::sync::Arc;

use hyperion_vault_core::IpAllowlist;

use crate::db::Db;
use crate::kms::KmsProvider;

pub struct AppState {
    pub db: Db,
    pub kms: Arc<dyn KmsProvider>,
    pub allowlist: IpAllowlist,
    pub trust_proxy: bool,
    pub node_name: String,
}

pub type SharedState = Arc<AppState>;

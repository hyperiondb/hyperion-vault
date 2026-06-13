pub use hyperion_vault_core as core;

pub use hyperion_vault_core::{
    auth, crypto, ip_allowlist, rotation, types, Error, IpAllowlist, Result, SecretKind,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod prelude {
    pub use hyperion_vault_core::auth::{fingerprint, generate_token, verify};
    pub use hyperion_vault_core::crypto::{open_envelope, seal_envelope, Envelope, KeyWrapper};
    pub use hyperion_vault_core::ip_allowlist::IpAllowlist;
    pub use hyperion_vault_core::rotation::{is_due, version_active, RotationPolicy};
    pub use hyperion_vault_core::types::{aad_for, SecretKind};
}

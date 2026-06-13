use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("encryption failed")]
    Encryption,

    #[error("decryption failed")]
    Decryption,

    #[error("key wrap failed")]
    KeyWrap,

    #[error("key unwrap failed")]
    KeyUnwrap,

    #[error("invalid IP allowlist entry: {0}")]
    InvalidAllowlist(String),

    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

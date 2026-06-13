use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::fill_random;

pub const TOKEN_BYTES: usize = 32;
pub const FINGERPRINT_LEN: usize = 32;

pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    fill_random(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn fingerprint(token: &str) -> [u8; FINGERPRINT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest);
    out
}

pub fn verify(token: &str, expected_fingerprint: &[u8]) -> bool {
    let computed = fingerprint(token);
    computed.as_slice().ct_eq(expected_fingerprint).into()
}

pub fn fingerprints_match(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

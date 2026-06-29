#![no_main]

use hyperion_vault_core::auth::{fingerprint, fingerprints_match, verify};
use libfuzzer_sys::fuzz_target;

// Token fingerprinting must be deterministic and self-verifying, and a
// length-mismatched expected fingerprint must never spuriously match.
fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let fp = fingerprint(token);
    assert_eq!(fp, fingerprint(token), "fingerprint must be deterministic");
    assert!(
        verify(token, &fp),
        "a token must verify against its own fingerprint"
    );
    assert!(fingerprints_match(&fp, &fp));
    assert!(
        !verify(token, &fp[..fp.len() - 1]),
        "a truncated expected fingerprint must not match"
    );
});

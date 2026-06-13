use std::collections::HashSet;

use hyperion_vault_core::auth::{
    fingerprint, fingerprints_match, generate_token, verify, FINGERPRINT_LEN,
};

#[test]
fn generated_tokens_are_unique() {
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..50_000 {
        assert!(seen.insert(generate_token()), "token collision generated");
    }
}

#[test]
fn generated_tokens_are_url_safe_and_long() {
    let token = generate_token();
    assert!(token.len() >= 43, "32 random bytes base64url is at least 43 chars");
    assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "token must be url-safe base64 without padding"
    );
}

#[test]
fn fingerprint_is_deterministic_and_fixed_length() {
    let token = generate_token();
    let a = fingerprint(&token);
    let b = fingerprint(&token);
    assert_eq!(a, b);
    assert_eq!(a.len(), FINGERPRINT_LEN);
}

#[test]
fn different_tokens_have_different_fingerprints() {
    let a = fingerprint(&generate_token());
    let b = fingerprint(&generate_token());
    assert_ne!(a, b);
}

#[test]
fn verify_accepts_matching_token() {
    let token = generate_token();
    let fp = fingerprint(&token);
    assert!(verify(&token, &fp));
}

#[test]
fn verify_rejects_wrong_token() {
    let fp = fingerprint(&generate_token());
    assert!(!verify(&generate_token(), &fp));
}

#[test]
fn verify_rejects_wrong_length_fingerprint() {
    let token = generate_token();
    assert!(!verify(&token, &[0u8; FINGERPRINT_LEN - 1]));
    assert!(!verify(&token, &[]));
    assert!(!verify(&token, &[0u8; FINGERPRINT_LEN + 5]));
}

#[test]
fn fingerprints_match_is_length_safe() {
    assert!(fingerprints_match(&[1, 2, 3], &[1, 2, 3]));
    assert!(!fingerprints_match(&[1, 2, 3], &[1, 2, 4]));
    assert!(!fingerprints_match(&[1, 2, 3], &[1, 2]));
    assert!(!fingerprints_match(&[1, 2, 3], &[]));
}

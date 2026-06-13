use std::collections::HashSet;

use hyperion_vault_core::crypto::{
    self, generate_dek, generate_nonce, open, open_envelope, seal, seal_envelope, LocalKeyWrapper,
    DEK_LEN, NONCE_LEN,
};
use hyperion_vault_core::types::aad_for;

#[test]
fn seal_open_round_trips() {
    let dek = generate_dek();
    let nonce = generate_nonce();
    let aad = aad_for("db/password", 1);
    let plaintext = b"super-secret-value";

    let ct = seal(&dek, &nonce, &aad, plaintext).unwrap();
    assert_ne!(ct.as_slice(), plaintext, "ciphertext must not equal plaintext");
    let pt = open(&dek, &nonce, &aad, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn ciphertext_tamper_is_rejected() {
    let dek = generate_dek();
    let nonce = generate_nonce();
    let aad = aad_for("name", 1);
    let mut ct = seal(&dek, &nonce, &aad, b"value").unwrap();
    ct[0] ^= 0x01;
    assert!(open(&dek, &nonce, &aad, &ct).is_err(), "tampered ciphertext must fail AEAD");
}

#[test]
fn tag_truncation_is_rejected() {
    let dek = generate_dek();
    let nonce = generate_nonce();
    let aad = aad_for("name", 1);
    let mut ct = seal(&dek, &nonce, &aad, b"value").unwrap();
    ct.pop();
    assert!(open(&dek, &nonce, &aad, &ct).is_err());
}

#[test]
fn nonce_tamper_is_rejected() {
    let dek = generate_dek();
    let nonce = generate_nonce();
    let aad = aad_for("name", 1);
    let ct = seal(&dek, &nonce, &aad, b"value").unwrap();
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0x01;
    assert!(open(&dek, &bad_nonce, &aad, &ct).is_err());
}

#[test]
fn wrong_key_is_rejected() {
    let dek = generate_dek();
    let other = generate_dek();
    let nonce = generate_nonce();
    let aad = aad_for("name", 1);
    let ct = seal(&dek, &nonce, &aad, b"value").unwrap();
    assert!(open(&other, &nonce, &aad, &ct).is_err());
}

#[test]
fn aad_binds_ciphertext_to_name_and_version() {
    let dek = generate_dek();
    let nonce = generate_nonce();
    let ct = seal(&dek, &nonce, &aad_for("secretA", 1), b"value").unwrap();

    assert!(
        open(&dek, &nonce, &aad_for("secretB", 1), &ct).is_err(),
        "ciphertext must not decrypt under a different secret name"
    );
    assert!(
        open(&dek, &nonce, &aad_for("secretA", 2), &ct).is_err(),
        "ciphertext must not decrypt under a different version"
    );
    assert!(open(&dek, &nonce, &aad_for("secretA", 1), &ct).is_ok());
}

#[test]
fn nonces_do_not_repeat() {
    let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
    for _ in 0..100_000 {
        assert!(seen.insert(generate_nonce()), "nonce collision generated");
    }
}

#[test]
fn data_keys_are_unique_and_high_entropy() {
    let mut seen: HashSet<[u8; DEK_LEN]> = HashSet::new();
    for _ in 0..50_000 {
        let dek = generate_dek();
        assert!(seen.insert(*dek), "DEK collision generated");
    }
}

#[test]
fn envelope_round_trips_through_wrapper() {
    let wrapper = LocalKeyWrapper::random();
    let aad = aad_for("api/key", 3);
    let env = seal_envelope(&wrapper, &aad, b"top-secret").unwrap();

    assert_ne!(env.ciphertext.as_slice(), b"top-secret");
    assert!(!env.wrapped_dek.is_empty());
    assert_eq!(open_envelope(&wrapper, &env, &aad).unwrap(), b"top-secret");
}

#[test]
fn envelope_wrapped_dek_is_randomized_per_call() {
    let wrapper = LocalKeyWrapper::random();
    let a = seal_envelope(&wrapper, b"aad", b"value").unwrap();
    let b = seal_envelope(&wrapper, b"aad", b"value").unwrap();
    assert_ne!(a.wrapped_dek, b.wrapped_dek, "DEK wrapping must be nondeterministic");
    assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must be nondeterministic");
}

#[test]
fn envelope_rejects_wrong_master_key() {
    let aad = aad_for("x", 1);
    let env = seal_envelope(&LocalKeyWrapper::random(), &aad, b"value").unwrap();
    let other = LocalKeyWrapper::random();
    assert!(open_envelope(&other, &env, &aad).is_err());
}

#[test]
fn envelope_rejects_tampered_wrapped_dek() {
    let wrapper = LocalKeyWrapper::random();
    let aad = aad_for("x", 1);
    let mut env = seal_envelope(&wrapper, &aad, b"value").unwrap();
    let last = env.wrapped_dek.len() - 1;
    env.wrapped_dek[last] ^= 0x01;
    assert!(open_envelope(&wrapper, &env, &aad).is_err());
}

#[test]
fn dek_from_slice_enforces_length() {
    assert!(crypto::dek_from_slice(&[0u8; DEK_LEN]).is_ok());
    assert!(crypto::dek_from_slice(&[0u8; DEK_LEN - 1]).is_err());
    assert!(crypto::dek_from_slice(&[0u8; DEK_LEN + 1]).is_err());
}

use std::time::Duration;

use hyperion_vault_core::rotation::{is_due, version_active, RotationPolicy};

#[test]
fn is_due_at_and_after_boundary() {
    assert!(!is_due(100, 101));
    assert!(is_due(100, 100));
    assert!(is_due(100, 99));
}

#[test]
fn next_rotation_advances_by_interval() {
    let policy = RotationPolicy::new(Duration::from_secs(3600), Duration::from_secs(300));
    assert_eq!(policy.next_rotation_unix(1_000), 4_600);
}

#[test]
fn grace_expiry_is_supersede_plus_grace() {
    let policy = RotationPolicy::new(Duration::from_secs(3600), Duration::from_secs(300));
    assert_eq!(policy.grace_expiry_unix(1_000), 1_300);
}

#[test]
fn current_version_never_expires() {
    assert!(version_active(i64::MAX, None));
    assert!(version_active(0, None));
}

#[test]
fn superseded_version_valid_until_grace_expiry() {
    let policy = RotationPolicy::new(Duration::from_secs(3600), Duration::from_secs(300));
    let expiry = policy.grace_expiry_unix(1_000);
    assert!(
        version_active(1_000, Some(expiry)),
        "valid immediately after rotation"
    );
    assert!(
        version_active(1_299, Some(expiry)),
        "valid within grace window"
    );
    assert!(
        !version_active(1_300, Some(expiry)),
        "invalid at grace expiry"
    );
    assert!(
        !version_active(2_000, Some(expiry)),
        "invalid after grace expiry"
    );
}

#[test]
fn zero_grace_supersedes_immediately() {
    let policy = RotationPolicy::new(Duration::from_secs(3600), Duration::from_secs(0));
    let expiry = policy.grace_expiry_unix(1_000);
    assert!(
        !version_active(1_000, Some(expiry)),
        "with zero grace the old version is invalid at once"
    );
}

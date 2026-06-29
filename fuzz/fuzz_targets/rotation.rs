#![no_main]

use std::time::Duration;

use arbitrary::Arbitrary;
use hyperion_vault_core::rotation::{is_due, version_active, RotationPolicy};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    interval_secs: u64,
    grace_secs: u64,
    from_unix: i64,
    now_unix: i64,
    expires_at: Option<i64>,
}

// Rotation timing arithmetic is saturating and must never overflow-panic, even
// at the i64/u64 extremes the fuzzer will reach.
fuzz_target!(|input: Input| {
    let policy = RotationPolicy::new(
        Duration::from_secs(input.interval_secs),
        Duration::from_secs(input.grace_secs),
    );
    let next = policy.next_rotation_unix(input.from_unix);
    let _ = policy.grace_expiry_unix(input.from_unix);
    let _ = is_due(input.now_unix, next);
    let _ = version_active(input.now_unix, input.expires_at);
});

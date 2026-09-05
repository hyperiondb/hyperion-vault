use std::time::Duration;

pub const MAX_ROTATION_INTERVAL_SECS: i64 = 100 * 365 * 24 * 60 * 60;
pub const MAX_GRACE_SECS: i64 = MAX_ROTATION_INTERVAL_SECS;

pub fn next_rotation_unix(from_unix: i64, interval_secs: i64) -> i64 {
    from_unix.saturating_add(interval_secs)
}

pub fn grace_expiry_unix(superseded_at_unix: i64, grace_secs: i64) -> i64 {
    superseded_at_unix.saturating_add(grace_secs)
}

pub fn next_version(current: i32) -> Option<i32> {
    current.checked_add(1)
}

#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    pub interval: Duration,
    pub grace: Duration,
}

impl RotationPolicy {
    pub fn new(interval: Duration, grace: Duration) -> Self {
        Self { interval, grace }
    }

    pub fn next_rotation_unix(&self, from_unix: i64) -> i64 {
        next_rotation_unix(from_unix, self.interval.as_secs() as i64)
    }

    pub fn grace_expiry_unix(&self, superseded_at_unix: i64) -> i64 {
        grace_expiry_unix(superseded_at_unix, self.grace.as_secs() as i64)
    }
}

pub fn is_due(now_unix: i64, next_rotation_unix: i64) -> bool {
    next_rotation_unix <= now_unix
}

pub fn version_active(now_unix: i64, expires_at_unix: Option<i64>) -> bool {
    match expires_at_unix {
        None => true,
        Some(expiry) => now_unix < expiry,
    }
}

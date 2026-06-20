use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn rfc3339(unix_secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_default()
}

pub fn rfc3339_opt(unix_secs: Option<i64>) -> Option<String> {
    unix_secs.map(rfc3339)
}

use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use std::ffi::CString;
use std::sync::OnceLock;

static DATABASE_CACHE: OnceLock<String> = OnceLock::new();

pub static ROTATION_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);
pub static SCAN_INTERVAL_SECS: GucSetting<i32> = GucSetting::<i32>::new(30);
pub static DATABASE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

pub fn init() {
    GucRegistry::define_bool_guc(
        c"hyperion_vault.rotation_enabled",
        c"Enable the automatic rotation supervisor background worker.",
        c"When on, the supervisor enqueues due automatic-secret rotations on the primary node only.",
        &ROTATION_ENABLED,
        GucContext::Sighup,
        GucFlags::default(),
    );

    GucRegistry::define_int_guc(
        c"hyperion_vault.scan_interval_secs",
        c"How often the rotation supervisor scans for secrets due for rotation.",
        c"Seconds between scans. The scan is a no-op on standby (read-only) nodes.",
        &SCAN_INTERVAL_SECS,
        1,
        86_400,
        GucContext::Sighup,
        GucFlags::default(),
    );

    GucRegistry::define_string_guc(
        c"hyperion_vault.database",
        c"Database the rotation supervisor connects to via SPI.",
        c"Must hold the vault schema created by this extension. Empty falls back to the POSTGRES_DB environment variable, then 'postgres'.",
        &DATABASE,
        GucContext::Postmaster,
        GucFlags::default(),
    );
}

pub fn rotation_enabled() -> bool {
    ROTATION_ENABLED.get()
}

pub fn scan_interval_secs() -> i32 {
    SCAN_INTERVAL_SECS.get()
}

pub fn database() -> String {
    DATABASE_CACHE
        .get_or_init(|| {
            DATABASE
                .get()
                .map(|value| value.to_string_lossy().into_owned())
                .filter(|value| !value.is_empty())
                .or_else(|| std::env::var("POSTGRES_DB").ok())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| String::from("postgres"))
        })
        .clone()
}

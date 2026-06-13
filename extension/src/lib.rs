use pgrx::bgworkers::{BackgroundWorker, BackgroundWorkerBuilder, BgWorkerStartTime, SignalWakeFlags};
use pgrx::prelude::*;
use std::time::Duration;

mod config;
mod schema;

pgrx::pg_module_magic!();

const ENQUEUE_SQL: &str = "SELECT vault.enqueue_due_rotations()";
const EXPIRE_SQL: &str = "SELECT vault.expire_grace_versions()";
const NOTIFY_SQL: &str = "NOTIFY vault_rotation";
const IN_RECOVERY_SQL: &str = "SELECT pg_is_in_recovery()";

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    if !unsafe { pg_sys::process_shared_preload_libraries_in_progress } {
        return;
    }

    config::init();

    BackgroundWorkerBuilder::new("hyperion_vault rotation supervisor")
        .set_function("hyperion_vault_rotation_main")
        .set_library("hyperion_vault")
        .set_restart_time(Some(Duration::from_secs(5)))
        .set_start_time(BgWorkerStartTime::ConsistentState)
        .load();
}

#[pg_guard]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn hyperion_vault_rotation_main(_arg: pg_sys::Datum) {
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some(&config::database()), None);

    pgrx::log!(
        "hyperion_vault: rotation supervisor started (database={}, interval={}s)",
        config::database(),
        config::scan_interval_secs()
    );

    while BackgroundWorker::wait_latch(Some(Duration::from_secs(
        config::scan_interval_secs() as u64,
    ))) {
        if !config::rotation_enabled() {
            continue;
        }

        BackgroundWorker::transaction(|| {
            let in_recovery = Spi::get_one::<bool>(IN_RECOVERY_SQL)
                .unwrap_or(Some(true))
                .unwrap_or(true);
            if in_recovery {
                return;
            }

            match Spi::get_one::<i32>(ENQUEUE_SQL) {
                Ok(Some(count)) if count > 0 => {
                    pgrx::log!("hyperion_vault: enqueued {} rotation job(s)", count);
                    let _ = Spi::run(NOTIFY_SQL);
                }
                Ok(_) => {}
                Err(err) => pgrx::warning!("hyperion_vault: enqueue_due_rotations failed: {err}"),
            }

            if let Err(err) = Spi::run(EXPIRE_SQL) {
                pgrx::warning!("hyperion_vault: expire_grace_versions failed: {err}");
            }
        });
    }

    pgrx::log!("hyperion_vault: rotation supervisor shutting down");
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn schema_and_functions_exist() {
        let status = Spi::get_one::<pgrx::JsonB>("SELECT vault.status()")
            .expect("SPI failed")
            .expect("status() returned NULL");
        assert!(status.0.get("secrets").is_some());
    }

    #[pg_test]
    fn enqueue_is_idempotent_for_no_due_secrets() {
        let enqueued = Spi::get_one::<i32>("SELECT vault.enqueue_due_rotations()")
            .expect("SPI failed")
            .expect("returned NULL");
        assert_eq!(enqueued, 0);
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}

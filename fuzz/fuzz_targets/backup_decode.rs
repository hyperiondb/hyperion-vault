#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::store::BackupData;

    // Restoring a backup parses untrusted JSON into BackupData; decoding must
    // never panic and a parsed value must survive an encode/decode round-trip.
    pub fn run(data: &[u8]) {
        if let Ok(backup) = serde_json::from_slice::<BackupData>(data) {
            let bytes = serde_json::to_vec(&backup).expect("a parsed backup must re-encode");
            let _ = serde_json::from_slice::<BackupData>(&bytes).expect("re-decode round-trip");
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| imp::run(data));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

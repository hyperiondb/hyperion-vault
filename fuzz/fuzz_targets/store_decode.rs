#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::store::codec::{decode, encode};
    use hyperion_vault_api::store::{
        AuditEntry, Command, KmsRewrapState, LockoutRecord, RoleRecord, SecretRecord, TokenRecord,
        VersionRecord,
    };

    // Decoding arbitrary bytes into any persisted/replicated record type must
    // never panic; a decoded command must survive an encode/decode round-trip.
    pub fn run(data: &[u8]) {
        if let Ok(command) = decode::<Command>(data) {
            let bytes = encode(&command).expect("a decoded command must re-encode");
            let _ = decode::<Command>(&bytes).expect("re-decode round-trip");
        }
        let _ = decode::<SecretRecord>(data);
        let _ = decode::<VersionRecord>(data);
        let _ = decode::<RoleRecord>(data);
        let _ = decode::<TokenRecord>(data);
        let _ = decode::<AuditEntry>(data);
        let _ = decode::<LockoutRecord>(data);
        let _ = decode::<KmsRewrapState>(data);
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| imp::run(data));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

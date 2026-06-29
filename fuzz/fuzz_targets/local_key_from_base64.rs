#![no_main]

use hyperion_vault_core::crypto::{open_envelope, seal_envelope, LocalKeyWrapper};
use libfuzzer_sys::fuzz_target;

// Decoding a base64 master key from untrusted text must never panic. Any key
// that parses is a valid 32-byte key and must seal/open a round-trip cleanly.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(wrapper) = LocalKeyWrapper::from_base64(text, "fuzz-key") {
        let env = seal_envelope(&wrapper, b"fuzz-aad", b"fuzz-plaintext")
            .expect("a valid 32-byte key must seal");
        let opened =
            open_envelope(&wrapper, &env, b"fuzz-aad").expect("authentic envelope must open");
        assert_eq!(opened.as_slice(), b"fuzz-plaintext");
    }
});

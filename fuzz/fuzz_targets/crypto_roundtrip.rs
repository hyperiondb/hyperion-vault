#![no_main]

use arbitrary::Arbitrary;
use hyperion_vault_core::crypto::{open_envelope, seal_envelope, LocalKeyWrapper};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    master: [u8; 32],
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    tamper_index: usize,
    tamper_xor: u8,
}

// AEAD envelope invariants: an authentic envelope round-trips exactly, while a
// changed AAD or a single tampered ciphertext byte must fail authentication.
fuzz_target!(|input: Input| {
    let wrapper = LocalKeyWrapper::new(input.master, "fuzz-key");

    let env = match seal_envelope(&wrapper, &input.aad, &input.plaintext) {
        Ok(env) => env,
        Err(_) => return,
    };

    let opened = open_envelope(&wrapper, &env, &input.aad).expect("authentic envelope must open");
    assert_eq!(opened.as_slice(), input.plaintext.as_slice());

    let wrong_aad: Vec<u8> = input.aad.iter().map(|byte| byte ^ 0xFF).collect();
    if wrong_aad != input.aad {
        assert!(
            open_envelope(&wrapper, &env, &wrong_aad).is_err(),
            "an AAD mismatch must never authenticate"
        );
    }

    if !env.ciphertext.is_empty() && input.tamper_xor != 0 {
        let mut tampered = env.clone();
        let idx = input.tamper_index % tampered.ciphertext.len();
        tampered.ciphertext[idx] ^= input.tamper_xor;
        assert!(
            open_envelope(&wrapper, &tampered, &input.aad).is_err(),
            "a tampered ciphertext must never authenticate"
        );
    }
});

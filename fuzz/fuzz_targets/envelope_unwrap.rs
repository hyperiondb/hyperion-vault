#![no_main]

use arbitrary::Arbitrary;
use hyperion_vault_core::crypto::{open, KeyWrapper, LocalKeyWrapper};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    master: [u8; 32],
    key_id: String,
    wrapped: Vec<u8>,
    nonce: [u8; 24],
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
}

// Feeding attacker-controlled bytes to the unwrap/decrypt paths must only ever
// return Ok/Err — never panic, slice-out-of-bounds, or abort.
fuzz_target!(|input: Input| {
    let wrapper = LocalKeyWrapper::new(input.master, input.key_id.clone());
    let _ = wrapper.unwrap_data_key(&input.wrapped, &input.key_id);
    let _ = open(&input.master, &input.nonce, &input.aad, &input.ciphertext);
});

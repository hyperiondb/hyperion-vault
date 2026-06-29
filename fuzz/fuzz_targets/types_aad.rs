#![no_main]

use arbitrary::Arbitrary;
use hyperion_vault_core::types::{aad_for, SecretFormat, SecretKind};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    name: String,
    version: i32,
    kind: String,
    format: String,
}

// Building AAD must never panic and must begin with the secret name, and the
// enum string parsers must round-trip through their canonical strings.
fuzz_target!(|input: Input| {
    let aad = aad_for(&input.name, input.version);
    assert!(
        aad.starts_with(input.name.as_bytes()),
        "aad must start with the secret name"
    );

    if let Some(kind) = SecretKind::parse(&input.kind) {
        assert_eq!(SecretKind::parse(kind.as_str()), Some(kind));
    }
    if let Some(format) = SecretFormat::parse(&input.format) {
        assert_eq!(SecretFormat::parse(format.as_str()), Some(format));
    }
});

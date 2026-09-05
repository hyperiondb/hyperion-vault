#![no_main]

// Pins the secret-version key contract described in VULN.md as VULN-2. Names
// and versions are validated on every write path, so `version_key` is only ever
// called with a valid pair; every scan of the byte range decides membership
// with `version_from_key`, which must never accept another secret's row.

#[cfg(feature = "api")]
mod imp {
    use arbitrary::Arbitrary;
    use hyperion_vault_api::store::engine::{
        version_from_key, version_key, version_lower, version_upper,
    };
    use hyperion_vault_core::{is_valid_secret_name, is_valid_secret_version};

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub name_a: String,
        pub name_b: String,
        pub version_a: i32,
        pub version_b: i32,
    }

    // The half-open range every version scan uses: `live_versions`,
    // `DeleteSecret` and the re-wrap sweep all read
    // `version_lower(name)..version_upper(name)`.
    fn inside_scan_range(key: &str, name: &str) -> bool {
        let lower = version_lower(name);
        let upper = version_upper(name);
        key >= lower.as_str() && key < upper.as_str()
    }

    pub fn run(input: Input) {
        let Input {
            name_a,
            name_b,
            version_a,
            version_b,
        } = input;

        // Isolation holds for arbitrary input, including a name a write path
        // would reject: a row belongs to a scan only if `version_from_key`
        // accepts it, and it must never accept another secret's row.
        if name_a != name_b {
            assert!(
                version_from_key(&name_a, &version_key(&name_b, version_b)).is_none(),
                "another secret's version row was accepted by this secret's scan"
            );
        }

        let valid_a = is_valid_secret_name(&name_a) && is_valid_secret_version(version_a);
        let valid_b = is_valid_secret_name(&name_b) && is_valid_secret_version(version_b);

        if valid_a {
            let key_a = version_key(&name_a, version_a);
            assert!(
                inside_scan_range(&key_a, &name_a),
                "a secret's own version row must fall inside its own scan range"
            );
            assert_eq!(
                version_from_key(&name_a, &key_a),
                Some(version_a),
                "a secret's own version row must parse back to its version"
            );
        }

        if valid_a && valid_b && name_a == name_b {
            assert!(
                version_a == version_b
                    || version_key(&name_a, version_a) != version_key(&name_a, version_b),
                "two versions of one secret must not share a key"
            );
            // `live_versions` sorts by the scan order, so byte order must
            // follow numeric order.
            if version_a < version_b {
                assert!(
                    version_key(&name_a, version_a) < version_key(&name_a, version_b),
                    "key byte order must match version numeric order"
                );
            }
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

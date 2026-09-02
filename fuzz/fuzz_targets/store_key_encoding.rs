#![no_main]

// KNOWN-FAILING TARGET. This reproduces the secret-version key collision
// described in VULN.md as VULN-2 (and in todo.md section 2.1). It is expected
// to exit non-zero within seconds until the key encoding (or every write path
// that reaches it) is fixed. `fuzz/run-all.sh` lists it under KNOWN_FAILING so
// a sweep still reports the other targets.

#[cfg(feature = "api")]
mod imp {
    use arbitrary::Arbitrary;
    use hyperion_vault_api::store::engine::{version_key, version_lower, version_upper};

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

        assert!(
            inside_scan_range(&version_key(&name_a, version_a), &name_a),
            "a secret's own version row must fall inside its own scan range"
        );

        assert!(
            version_a == version_b
                || version_key(&name_a, version_a) != version_key(&name_a, version_b),
            "two versions of one secret must not share a key"
        );

        // `live_versions` sorts by the scan order, so byte order must follow
        // numeric order.
        if version_a < version_b {
            assert!(
                version_key(&name_a, version_a) < version_key(&name_a, version_b),
                "key byte order must match version numeric order"
            );
        }

        // Isolation: one secret's rows must never be visible to, or deletable
        // by, a scan of a different secret.
        if name_a != name_b {
            assert!(
                !inside_scan_range(&version_key(&name_b, version_b), &name_a),
                "another secret's version row fell inside this secret's scan range"
            );
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

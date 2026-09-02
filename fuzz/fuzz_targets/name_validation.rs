#![no_main]

#[cfg(feature = "api")]
mod imp {
    use arbitrary::Arbitrary;
    use hyperion_vault_api::manage::validate_role_name;
    use hyperion_vault_api::service::{
        normalize_grace, validate_field, validate_name, validate_value,
    };

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub name: String,
        pub role_name: String,
        pub value: String,
        pub grace: Option<i64>,
    }

    // Pins the input contract the storage layer depends on: what a name that
    // reaches `version_key` may contain, and what `grace_secs` may be.
    pub fn run(input: Input) {
        let Input {
            name,
            role_name,
            value,
            grace,
        } = input;

        if validate_name(&name).is_ok() {
            assert!(
                (1..=255).contains(&name.len()),
                "an accepted secret name must be 1..=255 bytes"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.')),
                "an accepted secret name must stay inside [A-Za-z0-9-_/.]"
            );
            // The two bytes the version-key encoding reserves as separators.
            assert!(
                !name.contains('\u{0}') && !name.contains('\u{1}'),
                "an accepted secret name must not contain a version-key separator byte"
            );
        }

        if validate_role_name(&role_name).is_ok() {
            assert!(
                !role_name.trim().is_empty() && role_name.len() <= 255,
                "an accepted role name must be non-blank and at most 255 bytes"
            );
        }

        match normalize_grace(grace) {
            Ok(secs) => assert!(secs >= 0, "a normalized grace period must not be negative"),
            Err(_) => assert!(
                grace.is_some_and(|value| value < 0),
                "normalize_grace must only reject a negative grace period"
            ),
        }
        assert_eq!(
            normalize_grace(None).ok(),
            Some(0),
            "an absent grace period must normalize to zero"
        );

        if validate_value(&value).is_ok() {
            assert!(value.len() <= 1 << 16, "an accepted value must fit the cap");
        }
        if validate_field("password", &value).is_ok() {
            assert!(
                !value.is_empty() && value.len() <= 1 << 16,
                "an accepted field must be non-empty and fit the cap"
            );
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

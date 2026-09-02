#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::pg_apply::split_hostport;

    // `hosts` entries come from the `target` object of a create-secret request
    // body, so this splitter runs on caller-supplied text before a Postgres
    // connection is opened.
    pub fn run(raw: &str) {
        let (host, port) = split_hostport(raw);

        assert!(
            raw.starts_with(host),
            "the host must be a prefix of the input"
        );
        assert!(host.len() <= raw.len(), "the host must not grow the input");

        if !raw.contains(':') {
            assert_eq!(host, raw, "a colon-free input is entirely the host");
            assert_eq!(port, 5432, "a colon-free input takes the default port");
        }

        // A well-formed "host:port" must survive the split unchanged.
        if let Some((expected_host, expected_port)) = raw.rsplit_once(':') {
            if !expected_host.contains(':') {
                if let Ok(parsed) = expected_port.parse::<u16>() {
                    assert_eq!(host, expected_host, "host must round-trip");
                    assert_eq!(port, parsed, "port must round-trip");
                }
            }
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|raw: &str| imp::run(raw));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

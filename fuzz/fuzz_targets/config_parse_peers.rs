#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::config::parse_peers;

    // VAULT_PEERS is operator-supplied, not attacker-supplied, but a parse
    // panic here aborts startup rather than printing a usable error.
    pub fn run(raw: &str) {
        let Ok(peers) = parse_peers(raw) else {
            return;
        };
        assert!(
            peers.len() <= raw.matches(',').count() + 1,
            "the map cannot hold more peers than there are comma-separated entries"
        );
        for (id, addr) in &peers {
            assert!(
                !addr.is_empty(),
                "an accepted peer address must be non-empty"
            );
            assert_eq!(
                addr.trim(),
                addr,
                "an accepted peer address must be trimmed"
            );
            assert!(
                raw.contains(&id.to_string()),
                "an accepted peer id must appear in the input"
            );
            assert!(
                raw.contains(addr.as_str()),
                "an accepted peer address must appear in the input"
            );
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|raw: &str| imp::run(raw));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

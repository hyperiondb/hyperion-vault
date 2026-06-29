#![no_main]

use std::net::Ipv4Addr;

use hyperion_vault_core::IpAllowlist;
use libfuzzer_sys::fuzz_target;

// Parsing an untrusted allowlist spec must never panic, and a successfully
// parsed list must answer `contains` for any address without panicking.
fuzz_target!(|data: &[u8]| {
    let Ok(spec) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(list) = IpAllowlist::parse(spec) {
        assert_eq!(list.is_empty(), list.len() == 0);
        for ip in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            let _ = list.contains(ip);
        }
    }
});

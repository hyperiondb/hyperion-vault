#![no_main]

#[cfg(feature = "api")]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use arbitrary::Arbitrary;
    use axum::extract::ConnectInfo;
    use axum::http::header::HeaderValue;
    use axum::http::request::Parts;
    use axum::http::Request;
    use hyperion_vault_api::guards::client_ip;

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        pub header: Vec<u8>,
        pub send_header: bool,
        pub peer_is_v6: bool,
        pub peer_v4: [u8; 4],
        pub peer_v6: [u8; 16],
        pub peer_port: u16,
        pub with_connect_info: bool,
    }

    fn build(input: &Input) -> (Parts, Option<IpAddr>, Option<String>) {
        let peer: IpAddr = if input.peer_is_v6 {
            IpAddr::V6(Ipv6Addr::from(input.peer_v6))
        } else {
            IpAddr::V4(Ipv4Addr::from(input.peer_v4))
        };

        let mut request = Request::builder().body(()).expect("empty request");
        let mut header_text = None;
        if input.send_header {
            if let Ok(value) = HeaderValue::from_bytes(&input.header) {
                header_text = value.to_str().ok().map(|text| text.to_string());
                request.headers_mut().insert("x-forwarded-for", value);
            }
        }
        let mut parts = request.into_parts().0;
        let socket_ip = if input.with_connect_info {
            parts
                .extensions
                .insert(ConnectInfo(SocketAddr::new(peer, input.peer_port)));
            Some(peer)
        } else {
            None
        };
        (parts, socket_ip, header_text)
    }

    // `client_ip` decides the read allowlist check and the brute-force lockout
    // key, from a header the client controls.
    pub fn run(input: Input) {
        let (parts, socket_ip, header_text) = build(&input);

        // With the proxy untrusted the header must not be able to move the
        // result away from the transport peer, ever.
        assert_eq!(
            client_ip(&parts, false),
            socket_ip,
            "X-Forwarded-For must be ignored when VAULT_TRUST_PROXY is off"
        );

        // With the proxy trusted the result is either the peer or an address
        // spelled out in the first comma-separated field of the header.
        match client_ip(&parts, true) {
            None => assert!(
                socket_ip.is_none(),
                "a request with a transport peer must resolve to some address"
            ),
            Some(resolved) => {
                if Some(resolved) == socket_ip {
                    return;
                }
                let header = header_text.expect("a non-peer address must come from the header");
                let first = header.split(',').next().unwrap_or_default().trim();
                assert_eq!(
                    first.parse::<IpAddr>().ok(),
                    Some(resolved),
                    "a trusted-proxy address must be the first X-Forwarded-For field"
                );
            }
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

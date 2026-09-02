#![no_main]

#[cfg(feature = "api")]
mod imp {
    use axum::http::header::{HeaderValue, AUTHORIZATION};
    use axum::http::request::Parts;
    use axum::http::Request;
    use hyperion_vault_api::guards::bearer_token;

    fn parts_with_authorization(raw: &[u8]) -> Option<Parts> {
        let value = HeaderValue::from_bytes(raw).ok()?;
        let mut request = Request::builder().body(()).ok()?;
        request.headers_mut().insert(AUTHORIZATION, value);
        Some(request.into_parts().0)
    }

    // The Authorization header is attacker-controlled on every management
    // request. Parsing it must be total, and anything it returns must be a
    // literal, non-empty substring of what the client sent.
    pub fn run(data: &[u8]) {
        let Some(parts) = parts_with_authorization(data) else {
            return;
        };
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        match bearer_token(&parts) {
            None => {}
            Some(token) => {
                let header = header.expect("a token can only come from a UTF-8 header");
                assert!(!token.is_empty(), "an empty token must be rejected");
                assert!(
                    header.contains(&token),
                    "the returned token must appear verbatim in the header"
                );
                assert!(
                    token.trim() == token,
                    "the returned token must be trimmed of surrounding whitespace"
                );
                assert!(
                    header.starts_with("Bearer ") || header.starts_with("bearer "),
                    "a token must only be accepted from a 'Bearer '/'bearer ' scheme"
                );
            }
        }
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| imp::run(data));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

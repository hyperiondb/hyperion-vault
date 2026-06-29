#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::dto::{
        BatchGetRequest, CreateRoleRequest, CreateSecretRequest, CreateTokenRequest,
        PermissionRule, SetPermissionsRequest, UpdateSecretRequest, UserPass, VerifyRequest,
    };

    // HTTP request bodies are deserialized by the Axum Json extractor before any
    // handler logic. Decoding malformed JSON into any request DTO must never
    // panic — only produce a clean serde error.
    pub fn run(data: &[u8]) {
        let _ = serde_json::from_slice::<CreateSecretRequest>(data);
        let _ = serde_json::from_slice::<UpdateSecretRequest>(data);
        let _ = serde_json::from_slice::<BatchGetRequest>(data);
        let _ = serde_json::from_slice::<CreateRoleRequest>(data);
        let _ = serde_json::from_slice::<SetPermissionsRequest>(data);
        let _ = serde_json::from_slice::<CreateTokenRequest>(data);
        let _ = serde_json::from_slice::<VerifyRequest>(data);
        let _ = serde_json::from_slice::<PermissionRule>(data);
        let _ = serde_json::from_slice::<UserPass>(data);
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| imp::run(data));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

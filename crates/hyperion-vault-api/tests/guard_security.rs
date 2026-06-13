use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use hyperion_vault_api::config::{Config, KmsMode};

fn test_config(allowed_ips: &str) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        allowed_ips: allowed_ips.to_string(),
        trust_proxy: false,
        pg_hosts: vec!["127.0.0.1".to_string()],
        pg_port: 5432,
        pg_user: "vault_service".to_string(),
        pg_password: String::new(),
        pg_dbname: "postgres".to_string(),
        pool_max: 1,
        kms_mode: KmsMode::Local,
        kms_key_id: String::new(),
        local_master_key_b64: None,
        rotation_poll_secs: 60,
        dek_cache_ttl_secs: 0,
        kms_max_retries: 0,
        node_name: "test".to_string(),
    }
}

async fn app(allowed_ips: &str) -> Router {
    let state = hyperion_vault_api::build_state(&test_config(allowed_ips))
        .await
        .expect("build_state");
    hyperion_vault_api::routes::router(state)
}

fn with_ip(mut req: Request<Body>, ip: [u8; 4]) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 40000))));
    req
}

#[tokio::test]
async fn create_requires_admin_token() {
    let app = app("10.0.0.0/24").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/secrets")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"x","kind":"manual","value":"y"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_with_malformed_authorization_is_unauthorized() {
    let app = app("10.0.0.0/24").await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/secrets")
        .header("authorization", "Basic abc")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"x","kind":"manual","value":"y"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_from_disallowed_ip_is_forbidden() {
    let app = app("10.0.0.0/24").await;
    let req = with_ip(
        Request::builder()
            .uri("/v1/secrets/foo")
            .body(Body::empty())
            .unwrap(),
        [192, 168, 1, 1],
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn read_without_connect_info_is_forbidden() {
    let app = app("10.0.0.0/24").await;
    let req = Request::builder()
        .uri("/v1/secrets/foo")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn empty_allowlist_denies_all_reads() {
    let app = app("").await;
    let req = with_ip(
        Request::builder()
            .uri("/v1/secrets/foo")
            .body(Body::empty())
            .unwrap(),
        [10, 0, 0, 9],
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn verify_from_disallowed_ip_is_forbidden() {
    let app = app("10.0.0.0/24").await;
    let req = with_ip(
        Request::builder()
            .method("POST")
            .uri("/v1/secrets/foo/verify")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"x"}"#))
            .unwrap(),
        [203, 0, 113, 5],
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn healthz_is_public() {
    let app = app("10.0.0.0/24").await;
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

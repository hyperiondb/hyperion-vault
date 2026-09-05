use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use hyperion_vault_api::config::{Config, KmsMode, PgTlsMode};

const TOKEN: &str = "routing-test-token";
const CLIENT_IP: [u8; 4] = [10, 0, 0, 9];

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("hv-routing-test-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    path.to_string_lossy().into_owned()
}

fn test_config() -> Config {
    Config {
        node_id: 1,
        peers: BTreeMap::new(),
        api_listen: "127.0.0.1:0".parse().unwrap(),
        db_path: temp_db_path(),
        bootstrap_token: Some(TOKEN.to_string()),
        allowed_ips: "10.0.0.0/24".to_string(),
        trust_proxy: false,
        read_consistency_linearizable: false,
        kms_mode: KmsMode::Local,
        kms_key_id: String::new(),
        local_master_key_b64: None,
        raft_bind: "0.0.0.0".to_string(),
        cluster_token: None,
        cluster_auth_required: false,
        raft_peer_check: false,
        rotation_poll_secs: 60,
        pg_target_hosts: String::new(),
        pg_target_tls: PgTlsMode::Disable,
        pg_target_ca_file: None,
        dek_cache_ttl_secs: 0,
        kms_max_retries: 0,
        kms_rewrap_enabled: false,
        kms_rewrap_poll_secs: 86400,
        kms_rewrap_max_per_sec: 0,
        auth_max_failures: 0,
        auth_lockout_secs: 900,
        auth_window_secs: 300,
        token_touch_secs: 300,
    }
}

async fn app() -> Router {
    let state = hyperion_vault_api::build_state(&test_config())
        .await
        .expect("build_state");
    hyperion_vault_api::routes::router(state)
}

fn request(method: &str, uri: &str, body: Option<&str>, token: bool) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if token {
        builder = builder.header("authorization", format!("Bearer {TOKEN}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut req = builder
        .body(match body {
            Some(text) => Body::from(text.to_string()),
            None => Body::empty(),
        })
        .expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((CLIENT_IP, 40000))));
    req
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn seed(app: &Router, name: &str, value: &str) {
    let body = format!(
        r#"{{"name":"{name}","kind":"automatic","value":"{value}","rotation_interval_secs":3600}}"#
    );
    let (status, text) = call(app, request("POST", "/v1/secrets", Some(&body), true)).await;
    assert_eq!(status, StatusCode::CREATED, "seed {name}: {text}");
}

#[tokio::test]
async fn a_name_with_a_slash_is_readable_through_its_own_url() {
    let app = app().await;
    seed(&app, "db/password", "s3cr3t").await;

    let (status, text) = call(&app, request("GET", "/v1/secrets/db/password", None, false)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("s3cr3t"), "{text}");

    let (status, text) = call(
        &app,
        request("GET", "/v1/secrets/db%2Fpassword", None, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the encoded form must keep working");
    assert!(text.contains("s3cr3t"), "{text}");
}

#[tokio::test]
async fn a_name_with_a_slash_can_be_rotated_and_verified_through_its_own_url() {
    let app = app().await;
    seed(&app, "pg/app", "first").await;

    let (status, text) = call(
        &app,
        request(
            "POST",
            "/v1/secrets/pg/app/verify",
            Some(r#"{"value":"first"}"#),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains(r#""valid":true"#), "{text}");

    let (status, text) = call(
        &app,
        request("POST", "/v1/secrets/pg/app/rotate", Some(""), true),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains(r#""version":2"#), "{text}");
}

#[tokio::test]
async fn a_name_with_a_slash_can_be_updated_and_deleted_through_its_own_url() {
    let app = app().await;
    seed(&app, "svc/key", "one").await;

    let (status, text) = call(
        &app,
        request(
            "PUT",
            "/v1/secrets/svc/key",
            Some(r#"{"value":"two"}"#),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let (status, text) = call(&app, request("DELETE", "/v1/secrets/svc/key", None, true)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
}

#[tokio::test]
async fn an_unknown_action_suffix_is_not_found() {
    let app = app().await;
    seed(&app, "db/password", "s3cr3t").await;

    let (status, _text) = call(
        &app,
        request("POST", "/v1/secrets/db/password/bogus", Some(""), true),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_rejects_a_name_with_dot_segments() {
    let app = app().await;
    let (status, text) = call(
        &app,
        request(
            "POST",
            "/v1/secrets",
            Some(r#"{"name":"a/../b","kind":"manual","value":"x"}"#),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
}

#[tokio::test]
async fn create_rejects_an_empty_value_and_verify_rejects_an_empty_presentation() {
    let app = app().await;
    let (status, text) = call(
        &app,
        request(
            "POST",
            "/v1/secrets",
            Some(r#"{"name":"empty/one","kind":"manual","value":""}"#),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");

    seed(&app, "empty/two", "real").await;
    let (status, text) = call(
        &app,
        request(
            "POST",
            "/v1/secrets/empty/two/verify",
            Some(r#"{"value":""}"#),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains(r#""valid":false"#), "{text}");
}

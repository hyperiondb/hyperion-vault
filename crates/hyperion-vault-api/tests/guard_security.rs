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

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("hv-test-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    path.to_string_lossy().into_owned()
}

fn test_config(allowed_ips: &str) -> Config {
    config_with_lockout(allowed_ips, 0)
}

fn config_with_lockout(allowed_ips: &str, max_failures: u32) -> Config {
    Config {
        node_id: 1,
        peers: BTreeMap::new(),
        api_listen: "127.0.0.1:0".parse().unwrap(),
        db_path: temp_db_path(),
        bootstrap_token: None,
        allowed_ips: allowed_ips.to_string(),
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
        auth_max_failures: max_failures,
        auth_lockout_secs: 900,
        auth_window_secs: 300,
        token_touch_secs: 300,
    }
}

async fn app(allowed_ips: &str) -> Router {
    let state = hyperion_vault_api::build_state(&test_config(allowed_ips))
        .await
        .expect("build_state");
    hyperion_vault_api::routes::router(state)
}

const LOCKOUT_TOKEN: &str = "lockout-test-token";

async fn app_with_lockout(allowed_ips: &str, max_failures: u32) -> Router {
    let mut cfg = config_with_lockout(allowed_ips, max_failures);
    cfg.bootstrap_token = Some(LOCKOUT_TOKEN.to_string());
    let state = hyperion_vault_api::build_state(&cfg)
        .await
        .expect("build_state");
    hyperion_vault_api::routes::router(state)
}

async fn app_with_proxy(allowed_ips: &str, max_failures: u32) -> Router {
    let mut cfg = config_with_lockout(allowed_ips, max_failures);
    cfg.bootstrap_token = Some(LOCKOUT_TOKEN.to_string());
    cfg.trust_proxy = true;
    let state = hyperion_vault_api::build_state(&cfg)
        .await
        .expect("build_state");
    hyperion_vault_api::routes::router(state)
}

fn forwarded_request(
    method: &str,
    uri: &str,
    body: &str,
    token: bool,
    peer: [u8; 4],
    claimed: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-forwarded-for", claimed);
    if token {
        builder = builder.header("authorization", format!("Bearer {LOCKOUT_TOKEN}"));
    }
    with_ip(builder.body(Body::from(body.to_string())).unwrap(), peer)
}

async fn status_of(app: &Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(req).await.unwrap().status()
}

fn json_request(method: &str, uri: &str, body: &str, token: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if token {
        builder = builder.header("authorization", format!("Bearer {LOCKOUT_TOKEN}"));
    }
    with_ip(
        builder.body(Body::from(body.to_string())).unwrap(),
        [10, 0, 0, 5],
    )
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
async fn failed_verifies_do_not_disable_secret_reads() {
    let app = app_with_lockout("10.0.0.0/24", 3).await;

    let create = json_request(
        "POST",
        "/v1/secrets",
        r#"{"name":"db/password","kind":"manual","value":"right"}"#,
        true,
    );
    assert_eq!(status_of(&app, create).await, StatusCode::CREATED);

    for _ in 0..3 {
        let attempt = json_request(
            "POST",
            "/v1/secrets/db/password/verify",
            r#"{"value":"wrong"}"#,
            false,
        );
        assert_eq!(status_of(&app, attempt).await, StatusCode::OK);
    }

    let read = with_ip(
        Request::builder()
            .uri("/v1/secrets/db/password")
            .body(Body::empty())
            .unwrap(),
        [10, 0, 0, 5],
    );
    assert_eq!(
        status_of(&app, read).await,
        StatusCode::OK,
        "wrong values presented to verify must not cost the caller its secret reads"
    );

    let locked = json_request(
        "POST",
        "/v1/secrets/db/password/verify",
        r#"{"value":"wrong"}"#,
        false,
    );
    assert_eq!(
        status_of(&app, locked).await,
        StatusCode::TOO_MANY_REQUESTS,
        "verify itself must lock out after the configured number of failures"
    );
}

#[tokio::test]
async fn failed_token_auth_still_disables_secret_reads() {
    let app = app_with_lockout("10.0.0.0/24", 3).await;

    for _ in 0..3 {
        let bad_token = with_ip(
            Request::builder()
                .method("POST")
                .uri("/v1/secrets")
                .header("authorization", "Bearer wrong-token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"x","kind":"manual","value":"y"}"#))
                .unwrap(),
            [10, 0, 0, 5],
        );
        assert_eq!(status_of(&app, bad_token).await, StatusCode::UNAUTHORIZED);
    }

    let read = with_ip(
        Request::builder()
            .uri("/v1/secrets/anything")
            .body(Body::empty())
            .unwrap(),
        [10, 0, 0, 5],
    );
    assert_eq!(
        status_of(&app, read).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a bad admin token must still lock the client IP out of reads"
    );
}

#[tokio::test]
async fn a_forged_forwarded_address_cannot_lock_out_another_client() {
    let app = app_with_proxy("10.0.0.0/24", 3).await;
    let proxy = [172, 30, 0, 2];
    let attacker = [203, 0, 113, 9];
    let victim = "10.0.0.5";

    let create = forwarded_request(
        "POST",
        "/v1/secrets",
        r#"{"name":"db/password","kind":"manual","value":"right"}"#,
        true,
        proxy,
        victim,
    );
    assert_eq!(status_of(&app, create).await, StatusCode::CREATED);

    for _ in 0..3 {
        let forged = forwarded_request(
            "POST",
            "/v1/secrets/db/password/verify",
            r#"{"value":"wrong"}"#,
            false,
            attacker,
            victim,
        );
        assert_eq!(status_of(&app, forged).await, StatusCode::OK);
    }

    let victim_read = with_ip(
        Request::builder()
            .uri("/v1/secrets/db/password")
            .header("x-forwarded-for", victim)
            .body(Body::empty())
            .unwrap(),
        proxy,
    );
    assert_eq!(
        status_of(&app, victim_read).await,
        StatusCode::OK,
        "the claimed address must not decide whose counter is charged"
    );

    let attacker_again = forwarded_request(
        "POST",
        "/v1/secrets/db/password/verify",
        r#"{"value":"wrong"}"#,
        false,
        attacker,
        "10.0.0.6",
    );
    assert_eq!(
        status_of(&app, attacker_again).await,
        StatusCode::TOO_MANY_REQUESTS,
        "changing the claimed address must not reset the sender's own counter"
    );
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

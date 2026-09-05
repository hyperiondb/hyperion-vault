use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use hyperion_vault_api::clock::{now_unix, rfc3339};
use hyperion_vault_api::config::{Config, KmsMode, PgTlsMode};

const TOKEN: &str = "rotation-test-token";
const UNREACHABLE_TARGET: &str = "127.0.0.1:1";
const ROTATION_INTERVAL_SECS: i64 = 86400;
const APPLY_RETRY_SECS: i64 = 60;

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!(
        "hv-rotation-test-{}-{}.redb",
        std::process::id(),
        n
    ));
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
        pg_target_hosts: UNREACHABLE_TARGET.to_string(),
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

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    token: bool,
) -> (StatusCode, String) {
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
        .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 9], 40000))));

    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn create_body() -> String {
    format!(
        r#"{{"name":"pg/app","kind":"automatic","username":"app","password":"first",
            "rotation_interval_secs":{ROTATION_INTERVAL_SECS},"grace_period_secs":3600,
            "target":{{"type":"pg_replica","hosts":["{UNREACHABLE_TARGET}"],"database":"postgres"}}}}"#
    )
}

#[tokio::test]
async fn a_failed_target_apply_leaves_the_new_password_stored_and_retries_soon() {
    let app = app().await;
    let (status, text) = call(&app, "POST", "/v1/secrets", Some(&create_body()), true).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");

    let before = now_unix();
    let (status, text) = call(&app, "POST", "/v1/secrets/pg/app/rotate", Some(""), true).await;
    let after = now_unix();
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unreachable target must fail the call: {text}"
    );

    let (status, text) = call(&app, "GET", "/v1/secrets/pg/app", None, false).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        text.contains(r#""version":2"#),
        "the new version must be committed before the target apply is attempted: {text}"
    );
    assert!(
        !text.contains(r#""password":"first""#),
        "the stored password must be the newly generated one: {text}"
    );

    let (status, text) = call(&app, "GET", "/v1/secrets", None, true).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let retry_window: Vec<String> = (before..=after)
        .map(|at| rfc3339(at + APPLY_RETRY_SECS))
        .collect();
    assert!(
        retry_window.iter().any(|at| text.contains(at.as_str())),
        "a failed apply must schedule a retry about {APPLY_RETRY_SECS}s out, not a full interval: {text}"
    );
    assert!(
        !text.contains(rfc3339(before + ROTATION_INTERVAL_SECS).as_str()),
        "the next attempt must not wait for the full rotation interval: {text}"
    );
}

#[tokio::test]
async fn a_secret_without_a_target_rotates_normally() {
    let app = app().await;
    let create = r#"{"name":"svc/token","kind":"automatic","rotation_interval_secs":86400}"#;
    let (status, text) = call(&app, "POST", "/v1/secrets", Some(create), true).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");

    let (status, text) = call(&app, "POST", "/v1/secrets/svc/token/rotate", Some(""), true).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains(r#""version":2"#), "{text}");
}

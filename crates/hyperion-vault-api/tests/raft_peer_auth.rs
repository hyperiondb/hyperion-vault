use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use hyperion_vault_api::raft::server::ServerState;
use hyperion_vault_api::raft::{PeerAddrs, PeerAuth, RaftNode, TypeConfig};
use hyperion_vault_api::store::RedbStore;

const TOKEN: &str = "cluster-secret";
const DELETE_COMMAND: &str = r#"{"DeleteSecret":{"name":"db/password"}}"#;

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> PathBuf {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!("hv-peer-auth-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    path
}

fn peers() -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    map.insert(1, "127.0.0.1:17700".to_string());
    map.insert(2, "127.0.0.1:17701".to_string());
    map
}

async fn router(token: Option<&str>, required: bool, peer_check: bool) -> Router {
    let store = RedbStore::open(temp_db_path(), 1).expect("store");
    let auth = Arc::new(PeerAuth::new(token.map(str::to_string), required).expect("peer auth"));
    let node = RaftNode::start(store, 1, peers(), auth.clone())
        .await
        .expect("raft node");
    hyperion_vault_api::raft::server::router(ServerState {
        raft: node.raft.clone(),
        auth,
        peers: PeerAddrs::new(peer_check, &peers()).await,
    })
}

fn request(uri: &str, body: &str, token: Option<&str>, source: [u8; 4]) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let mut req = builder.body(Body::from(body.to_string())).expect("request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((source, 40000))));
    req
}

async fn status(app: &Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(req).await.expect("response").status()
}

fn append_body(leader: u64, committed: bool) -> String {
    let mut vote = openraft::Vote::new(9, leader);
    vote.committed = committed;
    let request: openraft::raft::AppendEntriesRequest<TypeConfig> =
        openraft::raft::AppendEntriesRequest {
            vote,
            prev_log_id: None,
            entries: vec![],
            leader_commit: None,
        };
    serde_json::to_string(&request).expect("encode")
}

#[tokio::test]
async fn without_a_credential_the_write_route_is_open_as_before() {
    let app = router(None, false, false).await;
    let sent = request("/raft/apply", DELETE_COMMAND, None, [127, 0, 0, 1]);
    assert_ne!(
        status(&app, sent).await,
        StatusCode::UNAUTHORIZED,
        "a node with no cluster token configured must behave as it did before"
    );
}

#[tokio::test]
async fn during_the_rollout_pass_a_wrong_credential_is_already_refused() {
    let app = router(Some(TOKEN), false, false).await;

    let missing = request("/raft/apply", DELETE_COMMAND, None, [127, 0, 0, 1]);
    assert_ne!(
        status(&app, missing).await,
        StatusCode::UNAUTHORIZED,
        "a peer that has not been rolled yet must still be accepted"
    );

    let wrong = request("/raft/apply", DELETE_COMMAND, Some("guess"), [127, 0, 0, 1]);
    assert_eq!(status(&app, wrong).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn when_required_every_route_needs_the_credential() {
    let app = router(Some(TOKEN), true, false).await;

    for uri in [
        "/raft/apply",
        "/raft/append",
        "/raft/vote",
        "/raft/snapshot",
    ] {
        let missing = request(uri, DELETE_COMMAND, None, [127, 0, 0, 1]);
        assert_eq!(
            status(&app, missing).await,
            StatusCode::UNAUTHORIZED,
            "{uri} must refuse a request with no credential"
        );
    }

    let right = request("/raft/apply", DELETE_COMMAND, Some(TOKEN), [127, 0, 0, 1]);
    assert_ne!(status(&app, right).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_source_address_that_is_not_a_peer_is_refused() {
    let app = router(Some(TOKEN), true, true).await;

    let stranger = request("/raft/apply", DELETE_COMMAND, Some(TOKEN), [203, 0, 113, 9]);
    assert_eq!(status(&app, stranger).await, StatusCode::FORBIDDEN);

    let peer = request("/raft/apply", DELETE_COMMAND, Some(TOKEN), [127, 0, 0, 1]);
    assert_ne!(status(&app, peer).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_append_from_an_unknown_node_id_or_with_an_uncommitted_vote_is_refused() {
    let app = router(Some(TOKEN), true, false).await;

    let stranger = request(
        "/raft/append",
        &append_body(99, true),
        Some(TOKEN),
        [127, 0, 0, 1],
    );
    assert_eq!(status(&app, stranger).await, StatusCode::FORBIDDEN);

    let uncommitted = request(
        "/raft/append",
        &append_body(2, false),
        Some(TOKEN),
        [127, 0, 0, 1],
    );
    assert_eq!(
        status(&app, uncommitted).await,
        StatusCode::BAD_REQUEST,
        "openraft asserts on an uncommitted vote, so it must be refused first"
    );
}

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyperion_vault_api::raft::{RaftNode, RaftStore};
use hyperion_vault_api::store::{
    Command, RedbStore, RoleRecord, SecretRecord, VaultReader, VaultWriter, VersionRecord,
};
use hyperion_vault_core::{SecretFormat, SecretKind};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("hv-raft-test-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    path.to_string_lossy().into_owned()
}

fn peer_map(addr: &str) -> BTreeMap<u64, String> {
    let mut peers = BTreeMap::new();
    peers.insert(1, addr.to_string());
    peers
}

async fn start_leader(addr: &str) -> std::sync::Arc<RaftNode> {
    let store = RedbStore::open(temp_db_path(), 1).expect("open redb store");
    let node = RaftNode::start(store, 1, peer_map(addr))
        .await
        .expect("raft node must construct (raft tables created)");
    node.bootstrap().await.expect("bootstrap");

    for _ in 0..100 {
        if node.raft.current_leader().await == Some(1) {
            return node;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("single node did not become leader within 10s");
}

#[tokio::test]
async fn empty_lowest_node_skips_init_when_a_peer_reports_a_cluster() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake peer");
    let peer_addr = listener.local_addr().expect("fake peer addr");
    let app = axum::Router::new().route(
        "/raft/initialized",
        axum::routing::get(|| async { axum::Json(true) }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let store = RedbStore::open(temp_db_path(), 1).expect("open redb store");
    let mut peers = BTreeMap::new();
    peers.insert(1, "127.0.0.1:17595".to_string());
    peers.insert(2, peer_addr.to_string());
    let node = RaftNode::start(store, 1, peers)
        .await
        .expect("raft node must construct");

    node.bootstrap().await.expect("bootstrap");

    assert!(
        !node
            .raft
            .is_initialized()
            .await
            .expect("is_initialized must not be fatal"),
        "a node that lost its local state must NOT re-initialize a cluster that already exists"
    );
}

#[tokio::test]
async fn raft_node_construction_creates_required_tables() {
    let store = RedbStore::open(temp_db_path(), 1).expect("open redb store");
    let node = RaftNode::start(store, 1, peer_map("127.0.0.1:17400")).await;
    assert!(
        node.is_ok(),
        "RaftNode::start must succeed; openraft reads raft_log/raft_meta during construction"
    );
}

#[tokio::test]
async fn write_through_raft_is_readable() {
    let node = start_leader("127.0.0.1:17401").await;
    let store = RaftStore::new(node);

    store
        .apply(Command::CreateRole {
            role: RoleRecord {
                name: "payment".to_string(),
                description: Some("scoped to stripe".to_string()),
                is_admin: false,
                permissions: vec![("create".to_string(), "stripe/*".to_string())],
                created_at: 0,
            },
        })
        .await
        .expect("create role through raft");

    let role = store
        .role("payment".to_string())
        .await
        .expect("read role")
        .expect("role exists after replication");
    assert_eq!(role.name, "payment");
    assert!(!role.is_admin);
    assert_eq!(
        role.permissions,
        vec![("create".to_string(), "stripe/*".to_string())]
    );
}

#[tokio::test]
async fn secret_version_round_trips_through_raft() {
    let node = start_leader("127.0.0.1:17402").await;
    let store = RaftStore::new(node);

    let secret = SecretRecord {
        name: "db/password".to_string(),
        kind: SecretKind::Manual,
        format: SecretFormat::Opaque,
        description: None,
        rotation_interval_secs: None,
        grace_secs: 0,
        current_version: 1,
        next_rotation_at: None,
        created_at: 0,
        updated_at: 0,
    };
    let version = VersionRecord {
        version: 1,
        kms_key_id: "local".to_string(),
        wrapped_dek: vec![1, 2, 3],
        nonce: vec![4; 24],
        ciphertext: vec![9, 9, 9],
        aad: b"db/password:1".to_vec(),
        created_at: 0,
        expires_at: None,
        wrapped_rotation_at: None,
    };

    store
        .apply(Command::CreateSecret { secret, version })
        .await
        .expect("create secret through raft");

    let (loaded, current) = store
        .current_version("db/password".to_string())
        .await
        .expect("read secret")
        .expect("secret exists after replication");
    assert_eq!(loaded.current_version, 1);
    assert_eq!(current.version, 1);
    assert_eq!(current.ciphertext, vec![9, 9, 9]);

    let conflict = store
        .apply(Command::CreateSecret {
            secret: SecretRecord {
                name: "db/password".to_string(),
                kind: SecretKind::Manual,
                format: SecretFormat::Opaque,
                description: None,
                rotation_interval_secs: None,
                grace_secs: 0,
                current_version: 1,
                next_rotation_at: None,
                created_at: 0,
                updated_at: 0,
            },
            version: VersionRecord {
                version: 1,
                kms_key_id: "local".to_string(),
                wrapped_dek: vec![],
                nonce: vec![0; 24],
                ciphertext: vec![],
                aad: vec![],
                created_at: 0,
                expires_at: None,
                wrapped_rotation_at: None,
            },
        })
        .await;
    assert!(conflict.is_err(), "duplicate secret name must conflict");
}

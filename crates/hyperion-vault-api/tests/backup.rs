use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyperion_vault_api::raft::{RaftNode, RaftStore};
use hyperion_vault_api::store::backup::BACKUP_VERSION;
use hyperion_vault_api::store::{
    BackupData, Command, RedbStore, RoleRecord, SecretRecord, TokenRecord, VaultReader,
    VaultWriter, VersionRecord,
};
use hyperion_vault_core::{SecretFormat, SecretKind};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> String {
    let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("hv-backup-test-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    path.to_string_lossy().into_owned()
}

fn sample_secret(name: &str, ciphertext: Vec<u8>) -> (SecretRecord, VersionRecord) {
    let secret = SecretRecord {
        name: name.to_string(),
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
        ciphertext,
        aad: format!("{name}:1").into_bytes(),
        created_at: 0,
        expires_at: None,
    };
    (secret, version)
}

fn peer_map(addr: &str) -> BTreeMap<u64, String> {
    let mut peers = BTreeMap::new();
    peers.insert(1, addr.to_string());
    peers
}

async fn start_leader(addr: &str) -> Arc<RaftNode> {
    let store = RedbStore::open(temp_db_path(), 1).expect("open redb store");
    let node = RaftNode::start(store, 1, peer_map(addr))
        .await
        .expect("raft node must construct");
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
async fn dump_restore_round_trips_and_replaces() {
    let source = RedbStore::open(temp_db_path(), 1).expect("open source");

    let (secret, version) = sample_secret("db/password", vec![9, 8, 7]);
    source
        .apply(Command::CreateSecret { secret, version })
        .await
        .expect("create secret");
    source
        .apply(Command::CreateRole {
            role: RoleRecord {
                name: "payments".to_string(),
                description: None,
                is_admin: false,
                permissions: vec![("create".to_string(), "stripe/*".to_string())],
                created_at: 0,
            },
        })
        .await
        .expect("create role");
    source
        .apply(Command::AddToken {
            token: TokenRecord {
                name: "ci".to_string(),
                role: Some("payments".to_string()),
                fingerprint: vec![7, 7, 7],
                created_at: 0,
                last_used_at: None,
                revoked_at: None,
            },
        })
        .await
        .expect("add token");

    let backup = source.dump().await.expect("dump");
    assert_eq!(backup.version, BACKUP_VERSION);
    assert_eq!(backup.secrets.len(), 1);

    let target = RedbStore::open(temp_db_path(), 2).expect("open target");
    let (stale, stale_version) = sample_secret("stale/secret", vec![1, 1, 1]);
    target
        .apply(Command::CreateSecret {
            secret: stale,
            version: stale_version,
        })
        .await
        .expect("seed stale data into target");

    target.restore(backup).await.expect("restore");

    let (loaded, current) = target
        .current_version("db/password".to_string())
        .await
        .expect("read restored secret")
        .expect("restored secret present");
    assert_eq!(loaded.current_version, 1);
    assert_eq!(current.ciphertext, vec![9, 8, 7]);

    let role = target
        .role("payments".to_string())
        .await
        .expect("read restored role")
        .expect("restored role present");
    assert_eq!(
        role.permissions,
        vec![("create".to_string(), "stripe/*".to_string())]
    );

    let token = target
        .token_by_fingerprint(vec![7, 7, 7])
        .await
        .expect("read restored token")
        .expect("restored token present");
    assert_eq!(token.name, "ci");

    assert!(
        target
            .secret("stale/secret".to_string())
            .await
            .expect("read stale")
            .is_none(),
        "restore must replace existing data, not merge it"
    );
}

#[tokio::test]
async fn restore_rejects_unknown_version() {
    let store = RedbStore::open(temp_db_path(), 1).expect("open");
    let bad = BackupData {
        version: BACKUP_VERSION + 1,
        ..Default::default()
    };
    assert!(
        store.restore(bad).await.is_err(),
        "restore must reject an unsupported backup version"
    );
}

#[tokio::test]
async fn backup_restore_through_raft_store() {
    let leader = start_leader("127.0.0.1:17410").await;
    let store = RaftStore::new(leader);

    store
        .apply(Command::CreateRole {
            role: RoleRecord {
                name: "reader".to_string(),
                description: None,
                is_admin: false,
                permissions: Vec::new(),
                created_at: 0,
            },
        })
        .await
        .expect("create role through raft");

    let backup = store.dump().await.expect("dump via raft store");
    assert!(
        backup.roles.iter().any(|(name, _)| name == "reader"),
        "dumped backup must contain the role written through raft"
    );

    store.restore(backup).await.expect("restore via raft store");

    let role = store
        .role("reader".to_string())
        .await
        .expect("read role after restore")
        .expect("role present after restore");
    assert_eq!(role.name, "reader");
}

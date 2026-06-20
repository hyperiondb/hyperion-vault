use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use openraft::error::{ClientWriteError, RaftError};
use openraft::{BasicNode, Config};

use super::network::NetworkFactory;
use super::store::{LogStore, StateMachine};
use super::types::{ApplyResult, NodeId, Raft};
use crate::store::engine::RedbStore;
use crate::store::{
    Command, LockoutRecord, RoleRecord, SecretRecord, StoreError, StoreResult, TokenRecord,
    VaultReader, VaultWriter, VersionRecord,
};

pub struct RaftNode {
    pub raft: Raft,
    store: Arc<RedbStore>,
    peers: BTreeMap<NodeId, BasicNode>,
    node_id: NodeId,
    http: reqwest::Client,
}

impl RaftNode {
    pub async fn start(
        store: Arc<RedbStore>,
        node_id: NodeId,
        peers: BTreeMap<NodeId, String>,
    ) -> Result<Arc<Self>> {
        let config = Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        };
        let config = Arc::new(config.validate().context("invalid raft config")?);

        super::store::init_raft_tables(&store.database()).context("init raft tables")?;

        let log_store = LogStore::new(store.database());
        let state_machine = StateMachine::new(store.clone());
        let network = NetworkFactory::new();

        let raft = Raft::new(node_id, config, network, log_store, state_machine)
            .await
            .context("failed to construct raft node")?;

        let basic_peers: BTreeMap<NodeId, BasicNode> = peers
            .iter()
            .map(|(id, addr)| (*id, BasicNode::new(addr)))
            .collect();

        Ok(Arc::new(Self {
            raft,
            store,
            peers: basic_peers,
            node_id,
            http: reqwest::Client::new(),
        }))
    }

    pub async fn bootstrap(&self) -> Result<()> {
        let lowest = self.peers.keys().next().copied().unwrap_or(self.node_id);
        if self.node_id == lowest {
            match self.raft.initialize(self.peers.clone()).await {
                Ok(_) => tracing::info!("raft cluster initialized"),
                Err(err) => {
                    tracing::info!(error = %err, "raft initialize skipped (already initialized)")
                }
            }
        }
        Ok(())
    }

    async fn write(&self, command: Command) -> StoreResult<()> {
        match self.raft.client_write(command.clone()).await {
            Ok(response) => outcome_to_result(response.data),
            Err(RaftError::APIError(ClientWriteError::ForwardToLeader(forward))) => {
                match forward.leader_node {
                    Some(node) => self.forward(&node.addr, &command).await,
                    None => Err(StoreError::Internal(anyhow!(
                        "no raft leader currently available"
                    ))),
                }
            }
            Err(err) => Err(StoreError::Internal(anyhow!("raft write failed: {err}"))),
        }
    }

    async fn forward(&self, addr: &str, command: &Command) -> StoreResult<()> {
        let url = format!("http://{addr}/raft/apply");
        let response = self
            .http
            .post(&url)
            .json(command)
            .send()
            .await
            .map_err(|e| StoreError::Internal(anyhow!(e)))?;
        if response.status().is_success() {
            let outcome: ApplyResult = response
                .json()
                .await
                .map_err(|e| StoreError::Internal(anyhow!(e)))?;
            outcome_to_result(outcome)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(StoreError::Internal(anyhow!(
                "leader rejected write ({status}): {body}"
            )))
        }
    }
}

fn outcome_to_result(outcome: ApplyResult) -> StoreResult<()> {
    match outcome {
        ApplyResult::Ok => Ok(()),
        ApplyResult::NotFound => Err(StoreError::NotFound),
        ApplyResult::Conflict(message) => Err(StoreError::Conflict(message)),
        ApplyResult::VersionConflict => Err(StoreError::VersionConflict),
    }
}

pub struct RaftStore {
    node: Arc<RaftNode>,
}

impl RaftStore {
    pub fn new(node: Arc<RaftNode>) -> Self {
        Self { node }
    }
}

#[async_trait]
impl VaultReader for RaftStore {
    async fn secret(&self, name: String) -> StoreResult<Option<SecretRecord>> {
        self.node.store.secret(name).await
    }
    async fn current_version(
        &self,
        name: String,
    ) -> StoreResult<Option<(SecretRecord, VersionRecord)>> {
        self.node.store.current_version(name).await
    }
    async fn version(&self, name: String, version: i32) -> StoreResult<Option<VersionRecord>> {
        self.node.store.version(name, version).await
    }
    async fn live_versions(&self, name: String, now: i64) -> StoreResult<Vec<VersionRecord>> {
        self.node.store.live_versions(name, now).await
    }
    async fn list_secrets(&self) -> StoreResult<Vec<SecretRecord>> {
        self.node.store.list_secrets().await
    }
    async fn due_rotations(&self, now: i64) -> StoreResult<Vec<SecretRecord>> {
        self.node.store.due_rotations(now).await
    }
    async fn role(&self, name: String) -> StoreResult<Option<RoleRecord>> {
        self.node.store.role(name).await
    }
    async fn list_roles(&self) -> StoreResult<Vec<RoleRecord>> {
        self.node.store.list_roles().await
    }
    async fn token_by_fingerprint(&self, fingerprint: Vec<u8>) -> StoreResult<Option<TokenRecord>> {
        self.node.store.token_by_fingerprint(fingerprint).await
    }
    async fn list_tokens(&self) -> StoreResult<Vec<TokenRecord>> {
        self.node.store.list_tokens().await
    }
    async fn lockout(&self, ip: String) -> StoreResult<Option<LockoutRecord>> {
        self.node.store.lockout(ip).await
    }
}

#[async_trait]
impl VaultWriter for RaftStore {
    async fn apply(&self, command: Command) -> StoreResult<()> {
        if command.is_local() {
            self.node.store.apply(command).await
        } else {
            self.node.write(command).await
        }
    }
}

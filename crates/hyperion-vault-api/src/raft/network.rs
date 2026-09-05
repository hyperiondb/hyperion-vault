use openraft::error::InstallSnapshotError;
use openraft::error::{NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;
use serde::de::DeserializeOwned;
use serde::Serialize;

use std::sync::Arc;

use super::peer::PeerAuth;
use super::types::{NodeId, TypeConfig};

#[derive(Debug, thiserror::Error)]
#[error("{url} returned HTTP {status}: {detail}")]
struct RpcStatusError {
    url: String,
    status: u16,
    detail: String,
}

pub struct NetworkFactory {
    client: reqwest::Client,
    auth: Arc<PeerAuth>,
}

impl NetworkFactory {
    pub fn new(auth: Arc<PeerAuth>) -> Self {
        Self {
            client: reqwest::Client::new(),
            auth,
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = NetworkConnection;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        NetworkConnection {
            client: self.client.clone(),
            auth: self.auth.clone(),
            target,
            addr: node.addr.clone(),
        }
    }
}

pub struct NetworkConnection {
    client: reqwest::Client,
    auth: Arc<PeerAuth>,
    target: NodeId,
    addr: String,
}

impl NetworkConnection {
    async fn rpc<Req, Resp, E>(
        &self,
        path: &str,
        req: Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let url = format!("http://{}/{}", self.addr, path);
        let mut request = self.client.post(&url).json(&req);
        if let Some(header) = self.auth.header() {
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        let response = request
            .send()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        if !status.is_success() {
            let detail: String = String::from_utf8_lossy(&bytes).chars().take(256).collect();
            let err = RpcStatusError {
                url,
                status: status.as_u16(),
                detail,
            };
            tracing::warn!(
                target_node = self.target,
                error = %err,
                body_bytes = bytes.len(),
                "raft RPC rejected by peer"
            );
            return Err(RPCError::Network(NetworkError::new(&err)));
        }
        let result: Result<Resp, RaftError<NodeId, E>> =
            serde_json::from_slice(&bytes).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TypeConfig> for NetworkConnection {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc("raft/append", rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        self.rpc("raft/snapshot", rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc("raft/vote", rpc).await
    }
}

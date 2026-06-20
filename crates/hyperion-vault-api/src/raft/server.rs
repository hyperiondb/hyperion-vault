use std::net::SocketAddr;

use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use tokio::net::TcpListener;

use super::types::{Raft, TypeConfig};
use crate::store::Command;

pub fn router(raft: Raft) -> Router {
    Router::new()
        .route("/raft/append", post(append))
        .route("/raft/snapshot", post(snapshot))
        .route("/raft/vote", post(vote))
        .route("/raft/apply", post(apply))
        .with_state(raft)
}

pub async fn serve(raft: Raft, listen: SocketAddr) -> anyhow::Result<()> {
    let app = router(raft);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind raft listener {listen}"))?;
    tracing::info!(%listen, "raft RPC listening");
    axum::serve(listener, app)
        .await
        .context("raft server error")?;
    Ok(())
}

async fn append(
    State(raft): State<Raft>,
    Json(rpc): Json<AppendEntriesRequest<TypeConfig>>,
) -> Response {
    Json(raft.append_entries(rpc).await).into_response()
}

async fn snapshot(
    State(raft): State<Raft>,
    Json(rpc): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Response {
    Json(raft.install_snapshot(rpc).await).into_response()
}

async fn vote(State(raft): State<Raft>, Json(rpc): Json<VoteRequest<u64>>) -> Response {
    Json(raft.vote(rpc).await).into_response()
}

async fn apply(State(raft): State<Raft>, Json(command): Json<Command>) -> Response {
    match raft.client_write(command).await {
        Ok(response) => (StatusCode::OK, Json(response.data)).into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, format!("{err}")).into_response(),
    }
}

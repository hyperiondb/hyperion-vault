use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use tokio::net::TcpListener;

use super::peer::{PeerAddrs, PeerAuth};
use super::types::{Raft, TypeConfig, RPC_BODY_LIMIT};
use crate::store::Command;

#[derive(Clone)]
pub struct ServerState {
    pub raft: Raft,
    pub auth: Arc<PeerAuth>,
    pub peers: Arc<PeerAddrs>,
}

pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/raft/append", post(append))
        .route("/raft/snapshot", post(snapshot))
        .route("/raft/vote", post(vote))
        .route("/raft/apply", post(apply))
        .route("/raft/initialized", get(initialized))
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard))
        .layer(DefaultBodyLimit::max(RPC_BODY_LIMIT))
        .with_state(state)
}

pub async fn serve(state: ServerState, listen: SocketAddr) -> anyhow::Result<()> {
    let app = router(state);
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind raft listener {listen}"))?;
    tracing::info!(%listen, "raft RPC listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("raft server error")?;
    Ok(())
}

async fn guard(State(state): State<ServerState>, request: Request, next: Next) -> Response {
    if state.peers.enabled() {
        let source = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        let allowed = match source {
            Some(ip) => state.peers.allows(ip).await,
            None => false,
        };
        if !allowed {
            tracing::warn!(
                source = ?source,
                path = %request.uri().path(),
                "raft RPC refused: source address is not a configured peer"
            );
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if !state.auth.accepts(presented) {
        tracing::warn!(
            path = %request.uri().path(),
            "raft RPC refused: missing or wrong cluster credential"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }

    next.run(request).await
}

async fn append(
    State(state): State<ServerState>,
    Json(rpc): Json<AppendEntriesRequest<TypeConfig>>,
) -> Response {
    if !state.peers.allows_leader(&rpc.vote) {
        return unknown_leader();
    }
    // openraft asserts on this, and the assertion kills the raft engine.
    if !rpc.vote.committed {
        return uncommitted_vote();
    }
    Json(state.raft.append_entries(rpc).await).into_response()
}

async fn snapshot(
    State(state): State<ServerState>,
    Json(rpc): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Response {
    if !state.peers.allows_leader(&rpc.vote) {
        return unknown_leader();
    }
    if !rpc.vote.committed {
        return uncommitted_vote();
    }
    Json(state.raft.install_snapshot(rpc).await).into_response()
}

async fn vote(State(state): State<ServerState>, Json(rpc): Json<VoteRequest<u64>>) -> Response {
    if !state.peers.allows_leader(&rpc.vote) {
        return unknown_leader();
    }
    Json(state.raft.vote(rpc).await).into_response()
}

async fn apply(State(state): State<ServerState>, Json(command): Json<Command>) -> Response {
    match state.raft.client_write(command).await {
        Ok(response) => (StatusCode::OK, Json(response.data)).into_response(),
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, format!("{err}")).into_response(),
    }
}

async fn initialized(State(state): State<ServerState>) -> Response {
    let value = state.raft.is_initialized().await.unwrap_or(false);
    Json(value).into_response()
}

fn uncommitted_vote() -> Response {
    tracing::warn!("raft RPC refused: append or snapshot carries an uncommitted vote");
    StatusCode::BAD_REQUEST.into_response()
}

fn unknown_leader() -> Response {
    tracing::warn!("raft RPC refused: vote names a node id that is not a configured peer");
    StatusCode::FORBIDDEN.into_response()
}

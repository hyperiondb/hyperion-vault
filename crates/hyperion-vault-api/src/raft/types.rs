use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::store::Command;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ApplyResult {
    #[default]
    Ok,
    NotFound,
    Conflict(String),
    VersionConflict,
}

pub const MAX_PAYLOAD_ENTRIES: u64 = 16;
pub const SNAPSHOT_MAX_CHUNK_SIZE: u64 = 256 * 1024;
pub const RPC_BODY_LIMIT: usize = 16 << 20;

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Command,
        R = ApplyResult,
        NodeId = u64,
        Node = openraft::BasicNode,
);

pub type Raft = openraft::Raft<TypeConfig>;
pub type NodeId = u64;

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_SECRET_FIELD_BYTES: u64 = 64 * 1024;
    const MAX_ENTRY_PLAINTEXT_BYTES: u64 = 2 * MAX_SECRET_FIELD_BYTES + 1024;
    const JSON_BYTE_ARRAY_EXPANSION: u64 = 4;
    const AXUM_DEFAULT_BODY_LIMIT: u64 = 2 * 1024 * 1024;

    fn max_entry_json_bytes() -> u64 {
        MAX_ENTRY_PLAINTEXT_BYTES * JSON_BYTE_ARRAY_EXPANSION
    }

    fn snapshot_chunk_json_bytes() -> u64 {
        SNAPSHOT_MAX_CHUNK_SIZE * JSON_BYTE_ARRAY_EXPANSION
    }

    #[test]
    fn append_batch_fits_the_rpc_body_limit() {
        assert!(MAX_PAYLOAD_ENTRIES * max_entry_json_bytes() <= RPC_BODY_LIMIT as u64);
    }

    #[test]
    fn snapshot_chunk_fits_the_rpc_body_limit() {
        assert!(snapshot_chunk_json_bytes() <= RPC_BODY_LIMIT as u64);
    }

    #[test]
    fn snapshot_chunk_fits_a_node_that_still_runs_the_axum_default() {
        assert!(snapshot_chunk_json_bytes() <= AXUM_DEFAULT_BODY_LIMIT);
    }
}

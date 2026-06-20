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

openraft::declare_raft_types!(
    pub TypeConfig:
        D = Command,
        R = ApplyResult,
        NodeId = u64,
        Node = openraft::BasicNode,
);

pub type Raft = openraft::Raft<TypeConfig>;
pub type NodeId = u64;

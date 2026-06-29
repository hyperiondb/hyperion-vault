#![no_main]

#[cfg(feature = "api")]
mod imp {
    use hyperion_vault_api::raft::TypeConfig;
    use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
    use openraft::Entry;

    // Raft RPC payloads arrive as JSON from peer nodes (raft/server.rs), and log
    // entries are re-read from disk (raft/store.rs). A deserialization panic on
    // any of these is a remotely/locally triggerable node crash, so every shape
    // must parse totally (Ok/Err only).
    pub fn run(data: &[u8]) {
        let _ = serde_json::from_slice::<AppendEntriesRequest<TypeConfig>>(data);
        let _ = serde_json::from_slice::<InstallSnapshotRequest<TypeConfig>>(data);
        let _ = serde_json::from_slice::<VoteRequest<u64>>(data);
        let _ = serde_json::from_slice::<Entry<TypeConfig>>(data);
    }
}

#[cfg(feature = "api")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| imp::run(data));

#[cfg(not(feature = "api"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

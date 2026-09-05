use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use openraft::Vote;
use tokio::sync::RwLock;

use super::types::NodeId;

const RESOLVE_TIMEOUT_SECS: u64 = 2;

pub struct PeerAuth {
    header: Option<String>,
    fingerprint: Option<[u8; hyperion_vault_core::auth::FINGERPRINT_LEN]>,
    required: bool,
}

impl PeerAuth {
    pub fn new(token: Option<String>, required: bool) -> Result<Self> {
        if required && token.is_none() {
            bail!("VAULT_CLUSTER_AUTH_REQUIRED=true needs VAULT_CLUSTER_TOKEN to be set");
        }
        Ok(Self {
            header: token.as_ref().map(|token| format!("Bearer {token}")),
            fingerprint: token.as_deref().map(hyperion_vault_core::auth::fingerprint),
            required,
        })
    }

    pub fn disabled() -> Self {
        Self {
            header: None,
            fingerprint: None,
            required: false,
        }
    }

    pub fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    pub fn required(&self) -> bool {
        self.required
    }

    pub fn configured(&self) -> bool {
        self.fingerprint.is_some()
    }

    pub fn accepts(&self, presented: Option<&str>) -> bool {
        let Some(expected) = &self.fingerprint else {
            return true;
        };
        let presented = presented.and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        });
        match presented {
            Some(token) => hyperion_vault_core::auth::verify(token.trim(), expected),
            None => !self.required,
        }
    }
}

pub struct PeerAddrs {
    enabled: bool,
    ids: BTreeSet<NodeId>,
    hosts: Vec<String>,
    resolved: RwLock<HashSet<IpAddr>>,
}

impl PeerAddrs {
    pub async fn new(enabled: bool, peers: &BTreeMap<NodeId, String>) -> Arc<Self> {
        let hosts: Vec<String> = peers.values().cloned().collect();
        let resolved = resolve(&hosts).await;
        Arc::new(Self {
            enabled,
            ids: peers.keys().copied().collect(),
            hosts,
            resolved: RwLock::new(resolved),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn resolved_len(&self) -> usize {
        self.resolved.read().await.len()
    }

    // Peer addresses are configured as host:port and a container's address can
    // change on restart, so a miss re-resolves once before it is refused.
    pub async fn allows(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }
        if self.resolved.read().await.contains(&ip) {
            return true;
        }
        let fresh = resolve(&self.hosts).await;
        let allowed = fresh.contains(&ip);
        *self.resolved.write().await = fresh;
        allowed
    }

    pub fn allows_leader(&self, vote: &Vote<NodeId>) -> bool {
        match vote.leader_id.voted_for() {
            Some(id) => self.ids.contains(&id),
            None => true,
        }
    }
}

async fn resolve(hosts: &[String]) -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    for host in hosts {
        let lookup = tokio::net::lookup_host(host.as_str());
        match tokio::time::timeout(std::time::Duration::from_secs(RESOLVE_TIMEOUT_SECS), lookup)
            .await
        {
            Ok(Ok(addrs)) => out.extend(addrs.map(|addr| addr.ip())),
            Ok(Err(err)) => {
                tracing::warn!(peer = %host, error = %err, "could not resolve a raft peer address")
            }
            Err(_) => tracing::warn!(peer = %host, "resolving a raft peer address timed out"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_token_accepts_everything() {
        let auth = PeerAuth::disabled();
        assert!(auth.accepts(None));
        assert!(auth.accepts(Some("Bearer anything")));
        assert!(auth.header().is_none());
    }

    #[test]
    fn a_configured_token_accepts_only_itself() {
        let auth = PeerAuth::new(Some("cluster-secret".to_string()), true).expect("auth");
        assert!(auth.accepts(Some("Bearer cluster-secret")));
        assert!(auth.accepts(Some("bearer cluster-secret")));
        assert!(!auth.accepts(Some("Bearer other")));
        assert!(!auth.accepts(None));
        assert_eq!(auth.header(), Some("Bearer cluster-secret"));
    }

    #[test]
    fn a_configured_token_still_accepts_a_peer_that_sends_none_until_it_is_required() {
        let auth = PeerAuth::new(Some("cluster-secret".to_string()), false).expect("auth");
        assert!(
            auth.accepts(None),
            "the rollout pass must not split a cluster"
        );
        assert!(!auth.accepts(Some("Bearer other")));
    }

    #[test]
    fn requiring_a_token_without_setting_one_is_refused() {
        assert!(PeerAuth::new(None, true).is_err());
    }
}

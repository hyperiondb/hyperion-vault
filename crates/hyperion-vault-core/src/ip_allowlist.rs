use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct IpAllowlist {
    nets: Vec<Ipv4Net>,
}

impl IpAllowlist {
    pub fn parse(spec: &str) -> Result<Self> {
        let mut nets = Vec::new();
        for raw in spec.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            let net = if token.contains('/') {
                Ipv4Net::from_str(token).map_err(|_| Error::InvalidAllowlist(token.to_string()))?
            } else {
                let addr = Ipv4Addr::from_str(token)
                    .map_err(|_| Error::InvalidAllowlist(token.to_string()))?;
                Ipv4Net::new(addr, 32).map_err(|_| Error::InvalidAllowlist(token.to_string()))?
            };
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

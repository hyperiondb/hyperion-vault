use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Manual,
    Automatic,
}

impl SecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::Manual => "manual",
            SecretKind::Automatic => "automatic",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "manual" => Some(SecretKind::Manual),
            "automatic" => Some(SecretKind::Automatic),
            _ => None,
        }
    }
}

pub fn aad_for(name: &str, version: i32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(name.len() + 12);
    aad.extend_from_slice(name.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(version.to_string().as_bytes());
    aad
}

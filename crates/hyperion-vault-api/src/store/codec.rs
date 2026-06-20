use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("encode store record")
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).context("decode store record")
}

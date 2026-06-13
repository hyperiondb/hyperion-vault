use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use hyperion_vault_core::crypto::{dek_from_slice, DataKey, Dek, KeyWrapper, LocalKeyWrapper};

use crate::config::{Config, KmsMode};

#[async_trait]
pub trait KmsProvider: Send + Sync {
    async fn generate_data_key(&self) -> Result<DataKey>;
    async fn decrypt_data_key(&self, wrapped: &[u8], key_id: &str) -> Result<Dek>;
}

pub async fn build(cfg: &Config) -> Result<Arc<dyn KmsProvider>> {
    match cfg.kms_mode {
        KmsMode::Aws => Ok(Arc::new(AwsKms::new(cfg.kms_key_id.clone()).await)),
        KmsMode::Local => {
            let wrapper = match &cfg.local_master_key_b64 {
                Some(encoded) => LocalKeyWrapper::from_base64(encoded, "local")?,
                None => LocalKeyWrapper::random(),
            };
            Ok(Arc::new(LocalKms { inner: wrapper }))
        }
    }
}

pub struct AwsKms {
    client: aws_sdk_kms::Client,
    key_id: String,
}

impl AwsKms {
    pub async fn new(key_id: String) -> Self {
        let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: aws_sdk_kms::Client::new(&sdk),
            key_id,
        }
    }
}

#[async_trait]
impl KmsProvider for AwsKms {
    async fn generate_data_key(&self) -> Result<DataKey> {
        let out = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("kms generate_data_key failed: {err:?}"))?;

        let plaintext = out.plaintext().context("kms returned no plaintext data key")?;
        let plaintext = dek_from_slice(plaintext.as_ref())?;
        let wrapped = out
            .ciphertext_blob()
            .context("kms returned no ciphertext blob")?
            .as_ref()
            .to_vec();
        let key_id = out.key_id().unwrap_or(&self.key_id).to_string();

        Ok(DataKey {
            plaintext,
            wrapped,
            key_id,
        })
    }

    async fn decrypt_data_key(&self, wrapped: &[u8], _key_id: &str) -> Result<Dek> {
        let out = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(wrapped.to_vec()))
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("kms decrypt failed: {err:?}"))?;

        let plaintext = out.plaintext().context("kms returned no plaintext")?;
        Ok(dek_from_slice(plaintext.as_ref())?)
    }
}

pub struct LocalKms {
    inner: LocalKeyWrapper,
}

#[async_trait]
impl KmsProvider for LocalKms {
    async fn generate_data_key(&self) -> Result<DataKey> {
        Ok(self.inner.generate_data_key()?)
    }

    async fn decrypt_data_key(&self, wrapped: &[u8], key_id: &str) -> Result<Dek> {
        Ok(self.inner.unwrap_data_key(wrapped, key_id)?)
    }
}

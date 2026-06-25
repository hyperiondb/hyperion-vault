use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use hyperion_vault_core::crypto::{dek_from_slice, DataKey, Dek, KeyWrapper, LocalKeyWrapper};

use crate::config::{Config, KmsMode};

#[async_trait]
pub trait KmsProvider: Send + Sync {
    async fn generate_data_key(&self, context: &[(&str, &str)]) -> Result<DataKey>;
    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<Dek>;

    async fn reencrypt_data_key(
        &self,
        wrapped: &[u8],
        source_key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<(Vec<u8>, String)>;

    async fn latest_rotation_at(&self) -> Result<Option<i64>>;
}

pub async fn build(cfg: &Config) -> Result<Arc<dyn KmsProvider>> {
    let inner: Arc<dyn KmsProvider> = match cfg.kms_mode {
        KmsMode::Aws => Arc::new(AwsKms::new(cfg.kms_key_id.clone()).await),
        KmsMode::Local => {
            let wrapper = match &cfg.local_master_key_b64 {
                Some(encoded) => LocalKeyWrapper::from_base64(encoded, "local")?,
                None => LocalKeyWrapper::random(),
            };
            Arc::new(LocalKms { inner: wrapper })
        }
    };

    if cfg.kms_max_retries == 0 {
        Ok(inner)
    } else {
        Ok(Arc::new(RetryingKms::new(inner, cfg.kms_max_retries)))
    }
}

pub struct RetryingKms {
    inner: Arc<dyn KmsProvider>,
    max_retries: u32,
}

impl RetryingKms {
    pub fn new(inner: Arc<dyn KmsProvider>, max_retries: u32) -> Self {
        Self { inner, max_retries }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        Duration::from_millis(100u64.saturating_mul(1u64 << attempt.min(6)))
    }
}

#[async_trait]
impl KmsProvider for RetryingKms {
    async fn generate_data_key(&self, context: &[(&str, &str)]) -> Result<DataKey> {
        let mut attempt = 0;
        loop {
            match self.inner.generate_data_key(context).await {
                Ok(value) => return Ok(value),
                Err(err) if attempt < self.max_retries => {
                    tracing::warn!(attempt, max = self.max_retries, error = %err, "kms generate_data_key failed; retrying");
                    tokio::time::sleep(self.backoff(attempt)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<Dek> {
        let mut attempt = 0;
        loop {
            match self.inner.decrypt_data_key(wrapped, key_id, context).await {
                Ok(value) => return Ok(value),
                Err(err) if attempt < self.max_retries => {
                    tracing::warn!(attempt, max = self.max_retries, error = %err, "kms decrypt failed; retrying");
                    tokio::time::sleep(self.backoff(attempt)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn reencrypt_data_key(
        &self,
        wrapped: &[u8],
        source_key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<(Vec<u8>, String)> {
        let mut attempt = 0;
        loop {
            match self
                .inner
                .reencrypt_data_key(wrapped, source_key_id, context)
                .await
            {
                Ok(value) => return Ok(value),
                Err(err) if attempt < self.max_retries => {
                    tracing::warn!(attempt, max = self.max_retries, error = %err, "kms re_encrypt failed; retrying");
                    tokio::time::sleep(self.backoff(attempt)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn latest_rotation_at(&self) -> Result<Option<i64>> {
        let mut attempt = 0;
        loop {
            match self.inner.latest_rotation_at().await {
                Ok(value) => return Ok(value),
                Err(err) if attempt < self.max_retries => {
                    tracing::warn!(attempt, max = self.max_retries, error = %err, "kms list_key_rotations failed; retrying");
                    tokio::time::sleep(self.backoff(attempt)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
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
    async fn generate_data_key(&self, context: &[(&str, &str)]) -> Result<DataKey> {
        let mut request = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes256);
        for &(key, value) in context {
            request = request.encryption_context(key, value);
        }
        let out = request
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("kms generate_data_key failed: {err:?}"))?;

        let plaintext = out
            .plaintext()
            .context("kms returned no plaintext data key")?;
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

    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<Dek> {
        let mut request = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(wrapped.to_vec()))
            .key_id(key_id);
        for &(key, value) in context {
            request = request.encryption_context(key, value);
        }
        let out = request
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("kms decrypt failed: {err:?}"))?;

        let plaintext = out.plaintext().context("kms returned no plaintext")?;
        Ok(dek_from_slice(plaintext.as_ref())?)
    }

    async fn reencrypt_data_key(
        &self,
        wrapped: &[u8],
        source_key_id: &str,
        context: &[(&str, &str)],
    ) -> Result<(Vec<u8>, String)> {
        let mut request = self
            .client
            .re_encrypt()
            .ciphertext_blob(Blob::new(wrapped.to_vec()))
            .source_key_id(source_key_id)
            .destination_key_id(&self.key_id);
        for &(key, value) in context {
            request = request
                .source_encryption_context(key, value)
                .destination_encryption_context(key, value);
        }
        let out = request
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("kms re_encrypt failed: {err:?}"))?;

        let blob = out
            .ciphertext_blob()
            .context("kms re_encrypt returned no ciphertext blob")?
            .as_ref()
            .to_vec();
        let key_id = out.key_id().unwrap_or(&self.key_id).to_string();
        Ok((blob, key_id))
    }

    async fn latest_rotation_at(&self) -> Result<Option<i64>> {
        let mut marker: Option<String> = None;
        let mut latest: Option<i64> = None;
        loop {
            let mut request = self.client.list_key_rotations().key_id(&self.key_id);
            if let Some(value) = &marker {
                request = request.marker(value);
            }
            let out = request
                .send()
                .await
                .map_err(|err| anyhow::anyhow!("kms list_key_rotations failed: {err:?}"))?;

            for entry in out.rotations() {
                if let Some(date) = entry.rotation_date() {
                    let secs = date.secs();
                    latest = Some(latest.map_or(secs, |current| current.max(secs)));
                }
            }

            if out.truncated() {
                marker = out.next_marker().map(|value| value.to_string());
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(latest)
    }
}

pub struct LocalKms {
    inner: LocalKeyWrapper,
}

#[async_trait]
impl KmsProvider for LocalKms {
    async fn generate_data_key(&self, _context: &[(&str, &str)]) -> Result<DataKey> {
        Ok(self.inner.generate_data_key()?)
    }

    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        key_id: &str,
        _context: &[(&str, &str)],
    ) -> Result<Dek> {
        Ok(self.inner.unwrap_data_key(wrapped, key_id)?)
    }

    async fn reencrypt_data_key(
        &self,
        wrapped: &[u8],
        source_key_id: &str,
        _context: &[(&str, &str)],
    ) -> Result<(Vec<u8>, String)> {
        Ok(self.inner.rewrap(wrapped, source_key_id)?)
    }

    async fn latest_rotation_at(&self) -> Result<Option<i64>> {
        Ok(None)
    }
}

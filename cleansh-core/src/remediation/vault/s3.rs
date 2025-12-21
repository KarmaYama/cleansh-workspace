// cleansh-core/src/remediation/vault/s3.rs
//! S3-backed implementation of the FingerprintVault.
//! Provides organization-wide secret ubiquity using a central JSON store.

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::Client;
use crate::remediation::fingerprint::SecretFingerprint;
use crate::remediation::vault::FingerprintVault;
use std::sync::Arc;

pub struct S3Vault {
    client: Client,
    bucket: String,
    key: String,
}

impl S3Vault {
    pub async fn new(bucket: &str, key: &str) -> Self {
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);
        Self {
            client,
            bucket: bucket.to_string(),
            key: key.to_string(),
        }
    }
}

#[async_trait]
impl FingerprintVault for S3Vault {
    /// Publishes a new fingerprint by fetching, merging, and re-uploading.
    /// Note: In a high-concurrency environment, this should use S3 conditional writes (ETags).
    async fn publish(&self, fingerprint: SecretFingerprint) -> Result<()> {
        let mut all = self.fetch_all().await.unwrap_or_default();
        
        // Only add if it's a new unique hash
        if !all.iter().any(|f| f.hash == fingerprint.hash) {
            all.push(fingerprint);
            let json = serde_json::to_vec(&all)?;

            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&self.key)
                .body(json.into())
                .content_type("application/json")
                .send()
                .await
                .context("Failed to upload updated fingerprints to S3")?;
        }
        Ok(())
    }

    /// Fetches the global list of fingerprints for ubiquitous masking.
    async fn fetch_all(&self) -> Result<Vec<SecretFingerprint>> {
        let resp = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await;

        match resp {
            Ok(output) => {
                let bytes = output.body.collect().await?.to_vec();
                let fingerprints: Vec<SecretFingerprint> = serde_json::from_slice(&bytes)?;
                Ok(fingerprints)
            }
            Err(_) => {
                // If file doesn't exist yet, return empty list
                Ok(Vec::new())
            }
        }
    }
}
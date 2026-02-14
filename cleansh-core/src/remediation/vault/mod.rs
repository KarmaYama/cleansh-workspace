// cleansh-core/src/remediation/vault/mod.rs
pub mod s3;
pub mod local; // Added

use anyhow::Result;
use async_trait::async_trait;
use crate::remediation::fingerprint::SecretFingerprint;

#[async_trait]
pub trait FingerprintVault: Send + Sync {
    async fn publish(&self, fingerprint: SecretFingerprint) -> Result<()>;
    async fn fetch_all(&self) -> Result<Vec<SecretFingerprint>>;
}
// cleansh-core/src/remediation/vault.rs
use anyhow::Result;
use async_trait::async_trait;
use crate::remediation::fingerprint::SecretFingerprint;

#[async_trait]
pub trait FingerprintVault: Send + Sync {
    /// Pushes a new fingerprint to the organization-wide store.
    async fn publish(&self, fingerprint: SecretFingerprint) -> Result<()>;

    /// Fetches all active fingerprints for the local instance to use.
    async fn fetch_all(&self) -> Result<Vec<SecretFingerprint>>;
}
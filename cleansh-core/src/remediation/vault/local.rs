// cleansh-core/src/remediation/vault/local.rs
//! Local file-backed implementation of the FingerprintVault.
//! Persists verified secret hashes to `~/.cleansh/vault.json` for permanent blocking.

use anyhow::{Context, Result};
use async_trait::async_trait;
use crate::remediation::fingerprint::SecretFingerprint;
use crate::remediation::vault::FingerprintVault;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub struct LocalVault {
    path: PathBuf,
}

impl LocalVault {
    pub fn new() -> Result<Self> {
        let mut path = dirs::home_dir()
            .context("Could not determine home directory for vault")?;
        path.push(".cleansh");
        path.push("vault.json");
        Ok(Self { path })
    }

    /// Ensure directory and file exist
    async fn init(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if !self.path.exists() {
            let empty_vec: Vec<SecretFingerprint> = Vec::new();
            let json = serde_json::to_string_pretty(&empty_vec)?;
            let mut file = fs::File::create(&self.path).await?;
            file.write_all(json.as_bytes()).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl FingerprintVault for LocalVault {
    async fn publish(&self, fingerprint: SecretFingerprint) -> Result<()> {
        self.init().await?;
        
        // Load existing
        let content = fs::read_to_string(&self.path).await?;
        let mut vault: Vec<SecretFingerprint> = serde_json::from_str(&content).unwrap_or_default();

        // Idempotency check: don't duplicate
        if !vault.iter().any(|f| f.hash == fingerprint.hash) {
            vault.push(fingerprint);
            
            // Save back
            let json = serde_json::to_string_pretty(&vault)?;
            let mut file = fs::File::create(&self.path).await?;
            file.write_all(json.as_bytes()).await?;
        }
        
        Ok(())
    }

    async fn fetch_all(&self) -> Result<Vec<SecretFingerprint>> {
        self.init().await?;
        let content = fs::read_to_string(&self.path).await?;
        let vault: Vec<SecretFingerprint> = serde_json::from_str(&content).unwrap_or_default();
        Ok(vault)
    }
}
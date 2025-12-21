// cleansh-core/src/remediation/fingerprint.rs
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFingerprint {
    pub hash: String,          // Salted SHA-256 of the raw secret
    pub provider: String,      // e.g., "github"
    pub detected_at: String,   // RFC3339 timestamp
    pub severity: String,      // "high", "critical"
}

impl SecretFingerprint {
    /// Creates a fingerprint from a raw secret string using a shared organization salt.
    pub fn from_secret(secret: &str, provider: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(secret.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            hash,
            provider: provider.to_string(),
            detected_at: chrono::Utc::now().to_rfc3339(),
            severity: "high".to_string(),
        }
    }
}
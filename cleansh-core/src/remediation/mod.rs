// cleansh-core/src/remediation/mod.rs
use anyhow::Result;
use async_trait::async_trait;
use crate::redaction_match::RedactionMatch;
use serde::{Deserialize, Serialize};

pub mod fingerprint;
pub mod vault;
pub mod providers;
pub mod orchestrator;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,      // Statistical anomaly only (e.g. random hex in a log)
    Medium,   // Anomaly + Contextual Keywords (e.g. "key: <random>")
    High,     // Regex Match + High Entropy (e.g. ghp_...)
    Critical, // Verified Live via API check
}

#[async_trait]
pub trait Remediator: Send + Sync {
    fn name(&self) -> &str;
    
    fn can_handle(&self, redaction: &RedactionMatch) -> bool;

    /// NEW: Verifies if the secret is active before attempting remediation.
    /// This prevents "dry-firing" at false positives or expired keys.
    async fn verify_live_status(&self, secret: &str) -> Result<bool>;
    
    /// The actual API call to neutralize the threat.
    async fn remediate(&self, redaction: &RedactionMatch) -> Result<RemediationOutcome>;
    
    fn auto_remediation_threshold(&self) -> ConfidenceLevel;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemediationOutcome {
    pub provider: String,
    pub action: String,
    pub successful: bool,
    pub message: String,
    pub confidence_boost: bool, // True if verification moved confidence to 'Critical'
}
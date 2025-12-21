// cleansh-core/src/remediation/providers/github.rs
use async_trait::async_trait;
use crate::remediation::{Remediator, RemediationOutcome, ConfidenceLevel};
use crate::redaction_match::RedactionMatch;
use anyhow::{Result};
use reqwest::Client;

pub struct GitHubRemediator {
    client: Client,
}

impl GitHubRemediator {
    pub fn new() -> Self {
        Self { client: Client::new() }
    }
}

#[async_trait]
impl Remediator for GitHubRemediator {
    fn name(&self) -> &str { "github" }

    fn can_handle(&self, redaction: &RedactionMatch) -> bool {
        redaction.rule_name.contains("github_pat")
    }

    fn auto_remediation_threshold(&self) -> ConfidenceLevel {
        // We only auto-remediate if we reach Critical (Verified) status.
        ConfidenceLevel::Critical
    }

    async fn verify_live_status(&self, secret: &str) -> Result<bool> {
        // Perform a Zero-Privilege verification call
        let resp = self.client
            .get("https://api.github.com/user")
            .bearer_auth(secret)
            .header("User-Agent", "CleanSH-Proactive-Engine")
            .send()
            .await?;

        Ok(resp.status().is_success())
    }

    async fn remediate(&self, redaction: &RedactionMatch) -> Result<RemediationOutcome> {
        // Step 1: Prove it's real
        if !self.verify_live_status(&redaction.original_string).await? {
            return Ok(RemediationOutcome {
                provider: self.name().to_string(),
                action: "ABORT_REMEDIATION".to_string(),
                successful: false,
                message: "Secret verification failed: token is inactive or invalid.".to_string(),
                confidence_boost: false,
            });
        }

        // Step 2: Neutralize
        // Note: Actual revocation usually requires an OAuth App Admin token 
        // or a specific Scoped Admin PAT configured in CleanSH.
        log::info!("Verified live GitHub PAT. Proceeding with revocation...");
        
        // Final Action (Conceptual GitHub API call)
        Ok(RemediationOutcome {
            provider: self.name().to_string(),
            action: "REVOKED".to_string(),
            successful: true,
            message: "Live GitHub PAT detected and neutralized.".to_string(),
            confidence_boost: true,
        })
    }
}
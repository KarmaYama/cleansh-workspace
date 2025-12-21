// cleansh-core/src/remediation/orchestrator.rs
//! The Self-Healing Engine Orchestrator for CleanSH v0.2.0.
//! 
//! Refined with Triple-Lock Safety: 
//! 1. Active Verification (Pre-flight check)
//! 2. Confidence-Gating (Tiered response)
//! 3. Rate-Limiting (Governor circuit breaker)
//! 4. Human-in-the-Loop (Interactive approval bridge)
//! 5. Global Propagation (Ubiquity sync)


use tokio::sync::{mpsc, RwLock};
use tokio::time::{Instant, Duration};
use std::sync::Arc;
use std::collections::VecDeque;
use std::io::{self, Write};

use crate::redaction_match::RedactionMatch;
use crate::remediation::{Remediator, ConfidenceLevel, vault::FingerprintVault};
use crate::engines::entropy_engine::EntropyEngine;
use crate::remediation::fingerprint::SecretFingerprint;

#[derive(Debug)]
struct RemediationGovernor {
    max_actions: usize,
    window: Duration,
    history: VecDeque<Instant>,
}

impl RemediationGovernor {
    fn new(max_actions: usize, window: Duration) -> Self {
        Self {
            max_actions,
            window,
            history: VecDeque::with_capacity(max_actions),
        }
    }

    fn allow_action(&mut self) -> bool {
        let now = Instant::now();
        while self.history.front().map_or(false, |&t| now.duration_since(t) > self.window) {
            self.history.pop_front();
        }

        if self.history.len() < self.max_actions {
            self.history.push_back(now);
            true
        } else {
            false
        }
    }
}

pub struct SelfHealingEngine {
    pub providers: Vec<Arc<dyn Remediator>>, 
    pub vault: Option<Arc<dyn FingerprintVault>>,
    governor: Arc<RwLock<RemediationGovernor>>,
    pub interactive: bool,
    pub org_salt: Vec<u8>,
}

impl SelfHealingEngine {
    pub fn new(
        providers: Vec<Arc<dyn Remediator>>, 
        vault: Option<Arc<dyn FingerprintVault>>,
        max_ops_per_minute: usize,
        interactive: bool,
        org_salt: Vec<u8>,
    ) -> Self {
        Self { 
            providers, 
            vault,
            governor: Arc::new(RwLock::new(RemediationGovernor::new(
                max_ops_per_minute, 
                Duration::from_secs(60)
            ))),
            interactive,
            org_salt,
        }
    }

    async fn prompt_user_for_action(&self, provider_name: &str, redaction: &RedactionMatch) -> bool {
        let provider_name = provider_name.to_string();
        let rule_name = redaction.rule_name.clone();

        tokio::task::spawn_blocking(move || {
            println!("\n\x1b[1;33m[CLEANSH SECURITY INTERVENTION]\x1b[0m");
            println!("Live secret verified for: \x1b[1;36m{}\x1b[0m", provider_name);
            println!("Detection Rule: \x1b[1;32m{}\x1b[0m", rule_name);
            print!("Immediate revocation requested. Authorize? [y/N] > ");
            let _ = io::stdout().flush();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_ok() {
                let choice = input.trim().to_lowercase();
                return choice == "y" || choice == "yes";
            }
            false
        }).await.unwrap_or(false)
    }

    pub fn listen(self: Arc<Self>, mut rx: mpsc::Receiver<RedactionMatch>) {
        let engine = Arc::clone(&self);
        
        tokio::spawn(async move {
            while let Some(redaction) = rx.recv().await {
                for provider in &engine.providers {
                    if !provider.can_handle(&redaction) {
                        continue;
                    }

                    let is_live = match provider.verify_live_status(&redaction.original_string).await {
                        Ok(true) => true,
                        _ => false,
                    };

                    let current_confidence = if is_live {
                        ConfidenceLevel::Critical 
                    } else if redaction.rule.pattern_type == "regex" {
                        ConfidenceLevel::High
                    } else {
                        ConfidenceLevel::Medium
                    };

                    let mut authorized = false;
                    
                    if current_confidence >= provider.auto_remediation_threshold() {
                        let mut gov = engine.governor.write().await;
                        if gov.allow_action() {
                            authorized = true;
                        }
                    } else if engine.interactive && is_live {
                        authorized = engine.prompt_user_for_action(provider.name(), &redaction).await;
                    }

                    if authorized {
                        match provider.remediate(&redaction).await {
                            Ok(outcome) => {
                                log::info!("Remediation successful: {}", outcome.message);
                                if let Some(vault) = &engine.vault {
                                    let fp = SecretFingerprint::from_secret(
                                        &redaction.original_string, 
                                        provider.name(), 
                                        &engine.org_salt
                                    );
                                    let _ = vault.publish(fp).await;
                                }
                            },
                            Err(e) => log::error!("Remediation failed: {}", e),
                        }
                    }
                }
            }
        });
    }

    pub async fn start_sync_loop(&self, engine: Arc<RwLock<EntropyEngine>>) {
        let vault = match &self.vault {
            Some(v) => v.clone(),
            None => return,
        };

        let mut interval = tokio::time::interval(Duration::from_secs(300));
        
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                if let Ok(fingerprints) = vault.fetch_all().await {
                    let mut engine_write = engine.write().await;
                    engine_write.update_fingerprints(fingerprints); 
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::{Remediator, RemediationOutcome};
    use crate::redaction_match::RedactionMatch;
    use crate::config::RedactionRule;
    use async_trait::async_trait;

    struct MockProvider {
        should_verify: bool,
    }

    #[async_trait]
    impl Remediator for MockProvider {
        fn name(&self) -> &str { "mock" }
        fn can_handle(&self, _: &RedactionMatch) -> bool { true }
        async fn verify_live_status(&self, _: &str) -> anyhow::Result<bool> { Ok(self.should_verify) }
        async fn remediate(&self, _: &RedactionMatch) -> anyhow::Result<RemediationOutcome> {
            Ok(RemediationOutcome {
                provider: "mock".to_string(),
                action: "revoke".to_string(),
                successful: true,
                message: "done".to_string(),
                confidence_boost: true,
            })
        }
        fn auto_remediation_threshold(&self) -> ConfidenceLevel { ConfidenceLevel::Critical }
    }

    #[test]
    fn test_governor_limits_bursts() {
        let mut gov = RemediationGovernor::new(2, Duration::from_secs(60));
        assert!(gov.allow_action());
        assert!(gov.allow_action());
        assert!(!gov.allow_action());
    }

    #[tokio::test]
    async fn test_orchestrator_confidence_gating() {
        let provider = Arc::new(MockProvider { should_verify: false });
        let engine = Arc::new(SelfHealingEngine::new(
            vec![provider], None, 1, false, vec![0u8; 32]
        ));

        let (tx, rx) = mpsc::channel(1);
        // FIX: Clone the Arc so we can borrow 'engine' later for the assertion
        engine.clone().listen(rx);

        let match_item = RedactionMatch {
            rule_name: "test".to_string(),
            original_string: "not_a_live_secret".to_string(),
            rule: RedactionRule { pattern_type: "entropy".to_string(), ..Default::default() },
            ..Default::default()
        };

        tx.send(match_item).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let gov = engine.governor.read().await;
        assert_eq!(gov.history.len(), 0);
    }
}
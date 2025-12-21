// cleansh-core/src/lib.rs
//! # CleanSH Core Library
//!
//! `cleansh-core` provides the fundamental, platform-independent logic for data sanitization,
//! redaction, and **proactive threat remediation**.
//!
//! Starting with v0.2.0, CleanSH transitions from a passive text filter to an active 
//! security partner. It implements a "Self-Healing Engine" that can verify and neutralize 
//! leaked secrets in real-time while maintaining zero-latency terminal performance.
//!
//! ## Core Architecture
//!
//! * **Sanitization Engines**: Locates sensitive patterns using Regex or statistical Entropy.
//! * **Self-Healing Orchestrator**: Manages the lifecycle of a detected secret—Verification, 
//!   Remediation (Revocation), and Global Fingerprint Propagation.
//! * **Triple-Lock Safety**: Ensures stability via Pre-flight checks, Confidence-Gating, 
//!   and a Remediation Governor (Rate-Limiter).
//!
//! ## Modules
//!
//! * `config`: Defines `RedactionRule`s and `RedactionConfig` for specifying sensitive patterns.
//! * `sanitizers`: Contains engine-specific logic for compiling rules.
//! * `validators`: Provides programmatic validation for specific data types.
//! * `redaction_match`: Defines data structures for detailed reporting of redaction events.
//! * `engine`: Defines the `SanitizationEngine` trait, enabling a modular design.
//! * `profiles`: Defines data structures for user-specified profiles and post-processing.
//! * `audit_log`: Defines the structure and logic for writing redaction events to a log file.
//! * `engines`: Contains concrete implementations of the `SanitizationEngine` trait.
//! * `headless`: Convenience wrappers for using core engines in a non-interactive mode.
//! * `remediation`: **(v0.2.0)** The Self-Healing framework, including providers and orchestrators.
//!
//! ## Usage Example (Proactive Healing)
//!
//! ```rust
//! use cleansh_core::{RedactionConfig, EntropyEngine, HeadlessEngineType, SanitizationEngine}; // <--- Fixed: Added SanitizationEngine trait import
//! use cleansh_core::remediation::orchestrator::SelfHealingEngine;
//! use tokio::sync::mpsc;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = RedactionConfig::load_default_rules()?;
//!     let mut engine = EntropyEngine::new(config)?;
//!
//!     // 1. Setup the Remediation Channel
//!     let (tx, rx) = mpsc::channel(100);
//!     
//!     // This method requires the SanitizationEngine trait to be in scope
//!     engine.set_remediation_tx(tx);
//!
//!     // 2. Initialize the Self-Healing Orchestrator
//!     // We wrap it in an Arc as required by the 'listen' method for async safety.
//!     let orchestrator = Arc::new(SelfHealingEngine::new(vec![], None, 5, true, vec![0u8; 32]));
//!     
//!     // 3. Start the background listener
//!     orchestrator.listen(rx);
//!
//!     Ok(())
//! }
//! ```
//!
//! ---
//! License: MIT OR APACHE 2.0

// Module declarations
pub mod audit_log;
pub mod config;
pub mod engine;
pub mod engines;
pub mod headless;
pub mod profiles;
pub mod redaction_match;
pub mod sanitizers;
pub mod validators;
pub mod errors;
pub mod remediation;

// Re-exports
pub use config::{
    merge_rules,
    RedactionConfig,
    RedactionRule,
    RedactionSummaryItem,
    RuleConfigNotFoundError,
    MAX_PATTERN_LENGTH,
};
pub use errors::CleanshError;
pub use engine::SanitizationEngine;
pub use engines::regex_engine::RegexEngine;
pub use engines::entropy_engine::EntropyEngine;
pub use redaction_match::{RedactionLog, RedactionMatch, redact_sensitive};
pub use profiles::{
    apply_profile_to_config,
    compute_run_seed,
    DedupeConfig,
    EngineOptions,
    format_token,
    load_profile_by_name,
    PostProcessingConfig,
    ProfileConfig,
    ProfileRule,
    profile_candidate_paths,
    ReportingConfig,
    SamplesConfig,
    sample_score_hex,
    select_samples_for_rule,
};
pub use audit_log::AuditLog;
pub use headless::{headless_sanitize_string, HeadlessEngineType};
pub use sanitizers::compiler::{compile_rules, CompiledRule, CompiledRules};

// Remediation re-exports for easy access
pub use remediation::{
    Remediator, 
    Remediator as RemediatorTrait, // Alias if needed for clarity
    RemediationOutcome, 
    ConfidenceLevel,
    orchestrator::SelfHealingEngine
};
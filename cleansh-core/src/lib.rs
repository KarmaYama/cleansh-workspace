// cleansh-core/src/lib.rs
//! # CleanSH Core Library
//!
//! `cleansh-core` provides the fundamental, platform-independent logic for data sanitization
//! and redaction. It defines the core data structures for redaction rules, provides mechanisms
//! for compiling these rules, and implements a pluggable `SanitizationEngine` trait for
//! applying redaction logic.
//!
//! The library is designed to be pure and stateless, focusing solely on the transformation
//! of input data based on defined rules, without concerns for I/O or application-specific
//! state management.
//!
//! ## Modules
//!
//! * `config`: Defines `RedactionRule`s and `RedactionConfig` for specifying sensitive patterns.
//! * `sanitizers`: Contains engine-specific logic for compiling rules, such as `regex_sanitizer`.
//! * `validators`: Provides programmatic validation for specific data types.
//! * `redaction_match`: Defines data structures for detailed reporting of redaction events.
//! * `engine`: Defines the `SanitizationEngine` trait, enabling a modular design.
//! * `profiles`: Defines data structures for user-specified profiles and post-processing.
//! * `audit_log`: Defines the structure and logic for writing redaction events to a log file.
//! * `engines`: Contains concrete implementations of the `SanitizationEngine` trait.
//! * `headless`: Convenience wrappers for using core engines in a non-interactive mode.
//!
//! ## Public API
//!
//! The public API provides a cohesive set of types and functions for configuring and running
//! a sanitization engine. Key components are organized by functionality:
//!
//! **Configuration & Rules**
//!
//! * [`RedactionConfig`]: Manages collections of `RedactionRule`s, including loading, merging, and filtering.
//! * [`RedactionRule`]: Defines a single rule for identifying and replacing sensitive patterns.
//! * [`merge_rules`]: Merges default and user-defined configurations.
//! * [`RedactionConfig::load_from_file`]: Loads rules from a YAML file.
//! * [`RedactionConfig::load_default_rules`]: Loads the built-in set of default rules.
//!
//! **Sanitization Engine**
//!
//! * [`SanitizationEngine`]: A trait for pluggable sanitization methods.
//! * [`RegexEngine`]: The concrete implementation of `SanitizationEngine` that uses regular expressions.
//!
//! **Headless Mode**
//!
//! * [`headless_sanitize_string`]: A convenience function for a full, one-shot sanitization.
//!
//! **Redaction Reporting**
//!
//! * [`RedactionMatch`]: A detailed record of a single matched and redacted item, including its location.
//! * [`RedactionSummaryItem`]: A summary of all matches for a specific rule.
//!
//! **Audit Logging**
//!
//! * [`AuditLog`]: Provides a high-level API for creating and writing structured redaction logs.
//!
//! ## Usage Example
//!
//! ```rust
//! use cleansh_core::{RedactionConfig, headless_sanitize_string, EngineOptions, HeadlessEngineType};
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!     // 1. Load default redaction rules.
//!     let default_config = RedactionConfig::load_default_rules()?;
//!
//!     // 2. Prepare some content to sanitize.
//!     let input = "My email is test@example.com and my SSN is 123-45-6789. Another email: user@domain.org.";
//!     println!("\nOriginal Input:\n{}", input);
//!
//!     // 3. Configure engine options.
//!     let options = EngineOptions::default();
//!     let source_id = "test_document.txt";
//!
//!     // 4. Sanitize the content in a single, headless function call.
//!     // We specify HeadlessEngineType::Regex to use the standard regex-based engine.
//!     let sanitized_output = headless_sanitize_string(
//!         default_config,
//!         options,
//!         input,
//!         source_id,
//!         HeadlessEngineType::Regex, 
//!     )?;
//!     println!("\nSanitized Output:\n{}", sanitized_output);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Error Handling
//!
//! The library uses `anyhow::Error` for fallible operations and defines specific error
//! types like `RuleConfigNotFoundError` for clearer error reporting.
//!
//! ## Design Principles
//!
//! * **Pluggable Architecture:** The `SanitizationEngine` trait allows for different
//!   sanitization methods (e.g., regex, entropy) to be swapped out seamlessly.
//! * **Stateless:** The core library does not maintain application state.
//! * **Testable:** Logic is easily unit-testable in isolation.
//! * **Extensible:** The design supports adding new rule types or engines with minimal
//!   changes to the core application logic.
//!
//! ---
//! License: BUSL-1.1

// All modules must be declared before they can be used.
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

// Correctly re-exporting modules and types from their canonical locations.
// This ensures the public API is clean and well-defined.

/// Re-exports the public configuration types and functions for managing redaction rules.
pub use config::{
    merge_rules,
    RedactionConfig,
    RedactionRule,
    RedactionSummaryItem,
    RuleConfigNotFoundError,
    MAX_PATTERN_LENGTH,
};

/// Re-exports the custom error type for clear error reporting.
pub use errors::CleanshError;

/// Re-exports types related to the core sanitization engine trait.
pub use engine::SanitizationEngine;

/// Re-exports the concrete `RegexEngine` and `EntropyEngine` implementations from their respective locations.
pub use engines::regex_engine::RegexEngine;
pub use engines::entropy_engine::EntropyEngine;

/// Re-exports types for detailed redaction matches and sensitive data reporting.
pub use redaction_match::{RedactionLog, RedactionMatch, redact_sensitive};

/// Re-exports types related to profile configuration, which allows for custom
/// redaction behavior and reporting.
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

/// Re-exports the AuditLog type for handling redaction event logging.
pub use audit_log::AuditLog;

/// Re-exports types and functions for one-shot, non-interactive use.
pub use headless::{headless_sanitize_string, HeadlessEngineType};

// Re-export key types from the sanitizers::compiler module for advanced usage.
// This is the correct path for `CompiledRule` and `CompiledRules`.
pub use sanitizers::compiler::{compile_rules, CompiledRule, CompiledRules};
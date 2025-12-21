// cleansh-core/src/engine.rs
//! Defines the core SanitizationEngine trait and related data structures.
//!
//! The `SanitizationEngine` trait provides a pluggable interface for different
//! sanitization methods (e.g., regex, entropy). This module defines the
//! contract that all such engines must adhere to, ensuring a consistent
//! and interchangeable core API for `cleansh`.
//!
//! License: MIT OR APACHE 2.0

use anyhow::Result;
use tokio::sync::mpsc;

// Publicly exposed types from other modules
use crate::config::{RedactionConfig, RedactionSummaryItem};
use crate::profiles::EngineOptions;
use crate::sanitizers::compiler::CompiledRules;
use crate::audit_log::AuditLog;
use crate::redaction_match::RedactionMatch;

/// A trait that defines the core functionality of a sanitization engine.
///
/// This trait decouples the high-level application logic from the specific
/// implementation of a sanitization method, allowing for different engines
/// to be used interchangeably.
pub trait SanitizationEngine: Send + Sync {
    /// Performs full sanitization on the provided content.
    ///
    /// This method is responsible for finding all sensitive data, applying
    /// redactions, and generating a summary of all matched items. It returns
    /// the fully sanitized content and a summary of all redaction events.
    ///
    /// # Arguments
    /// * `content` - The input string to sanitize.
    /// * `source_id` - The name or identifier of the source being processed.
    /// * `run_id` - A unique identifier for the current sanitization run.
    /// * `input_hash` - A hash of the original input content for integrity checks.
    /// * `user_id` - The user ID associated with the sanitization run.
    /// * `reason` - The reason for the sanitization.
    /// * `outcome` - The outcome of the sanitization.
    /// * `audit_log` - An optional mutable reference to an `AuditLog` instance for logging events.
    fn sanitize(
        &self,
        content: &str,
        source_id: &str,
        run_id: &str,
        input_hash: &str,
        user_id: &str,
        reason: &str,
        outcome: &str,
        audit_log: Option<&mut AuditLog>,
    ) -> Result<(String, Vec<RedactionSummaryItem>)>;

    /// Analyzes the provided content for sensitive data without performing redaction.
    ///
    /// This method is used specifically for the `--stats-only` command. It returns
    /// a summary of all matched items, but the original content is not modified.
    ///
    /// # Arguments
    /// * `content` - The input string to scan.
    /// * `source_id` - An identifier for the source of the content (e.g., a file path).
    fn analyze_for_stats(&self, content: &str, source_id: &str) -> Result<Vec<RedactionSummaryItem>>;

    /// Finds all matches and prepares them for an interactive TUI session.
    ///
    /// This method returns a flattened vector of `RedactionMatch` instances,
    /// each with a stable sort order, a source ID, and a canonical hash.
    ///
    /// # Arguments
    /// * `content` - The input string to scan.
    /// * `source_id` - An identifier for the source of the content (e.g., a file path).
    fn find_matches_for_ui(&self, content: &str, source_id: &str) -> Result<Vec<RedactionMatch>>;

    /// Returns the statistical "heat" (entropy) for each character in the input.
    /// This allows the UI to render heatmaps via dependency inversion.
    fn get_heat_scores(&self, content: &str) -> Vec<f64>;

    /// Returns a reference to the `CompiledRules` used by the engine.
    ///
    /// This is used by external components, such as the statistics command,
    /// to access and display information about the rules without needing
    /// to recompile them.
    fn compiled_rules(&self) -> &CompiledRules;

    /// Returns a reference to the engine's configuration.
    fn get_rules(&self) -> &RedactionConfig;

    /// Returns a reference to the engine's options.
    fn get_options(&self) -> &EngineOptions;

    /// Sets the remediation channel for the self-healing orchestrator.
    /// This enables v0.2.0 "Tee-Logic" where matches are sent asynchronously for healing.
    fn set_remediation_tx(&mut self, tx: mpsc::Sender<RedactionMatch>);
}
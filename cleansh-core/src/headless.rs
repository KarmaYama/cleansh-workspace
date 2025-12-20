// cleansh-core/src/headless.rs
// File: cleansh-core/src/headless.rs

//! `headless.rs`
//! Convenience wrappers for using core engines in headless mode (non-UI).
//! Provides helper functions for a full, one-shot sanitization of strings.
//! 
//! Now supports selecting between the standard Regex engine and the advanced Entropy engine.

use anyhow::Result;
use crate::config::RedactionConfig;
use crate::profiles::EngineOptions;
use crate::engines::regex_engine::RegexEngine;
use crate::engines::entropy_engine::EntropyEngine;
use crate::engine::SanitizationEngine;

/// Enum to select which sanitization engine to use in headless mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadlessEngineType {
    Regex,
    Entropy,
}

/// Fully sanitizes an input string by finding and applying all redaction matches.
/// This function is the primary entry point for non-interactive (headless) use.
///
/// # Arguments
///
/// * `config` - The merged RedactionConfig (defaults + optional user overrides).
/// * `options` - EngineOptions (run_seed, etc).
/// * `content` - The string to be sanitized.
/// * `source_id` - A stable identifier for the input (file path or pseudo id).
/// * `engine_type` - Which engine to use (`Regex` or `Entropy`).
pub fn headless_sanitize_string(
    config: RedactionConfig,
    options: EngineOptions,
    content: &str,
    source_id: &str,
    engine_type: HeadlessEngineType,
) -> Result<String> {
    // Dynamically instantiate the selected engine behind the SanitizationEngine trait.
    let engine: Box<dyn SanitizationEngine> = match engine_type {
        HeadlessEngineType::Regex => {
            Box::new(RegexEngine::with_options(config, options)?)
        },
        HeadlessEngineType::Entropy => {
            Box::new(EntropyEngine::with_options(config, options)?)
        },
    };

    // The `sanitize` method takes audit log parameters, which we can provide as empty placeholders
    // for this headless convenience wrapper.
    let (sanitized_content, _) = engine.sanitize(
        content,
        source_id,
        "", // run_id
        "", // input_hash
        "", // user_id
        "", // reason
        "", // outcome
        None, // No audit log
    )?;

    Ok(sanitized_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionRule;
    use crate::profiles::EngineOptions;
    use anyhow::Result;

    #[test]
    fn test_headless_sanitize_string_regex() -> Result<()> {
        let content = "My email is test@example.com, and another is another@example.net.";
        let config = RedactionConfig {
            rules: vec![
                RedactionRule {
                    name: "email".to_string(),
                    pattern: Some("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[A-Za-z]{2,})".to_string()),
                    enabled: Some(true),
                    severity: Some("high".to_string()),
                    replace_with: "[EMAIL]".to_string(),
                    description: Some("Matches email addresses".to_string()),
                    multiline: false,
                    dot_matches_new_line: false,
                    programmatic_validation: false,
                    opt_in: false,
                    tags: None,
                    pattern_type: "regex".to_string(),
                    version: "0.1.8".to_string(),
                    created_at: "2025-01-01T00:00:00Z".to_string(),
                    updated_at: "2025-01-01T00:00:00Z".to_string(),
                    author: "Obscura Team".to_string(),
                },
            ],
        };
        let options = EngineOptions::default();
        
        let sanitized_content = headless_sanitize_string(
            config, 
            options, 
            content, 
            "test_input",
            HeadlessEngineType::Regex
        )?;
        
        let expected_output = "My email is [EMAIL], and another is [EMAIL].";
        assert_eq!(sanitized_content, expected_output);
        
        Ok(())
    }

    #[test]
    fn test_headless_sanitize_string_entropy() -> Result<()> {
        // Simple test to ensure the entropy path compiles and runs.
        // Note: Without the full EntropyEngine logic populated with complex rules/context,
        // this primarily validates the plumbing.
        let content = "Some random high entropy string like 8x9#bF2!kL in text.";
        
        // Entropy engine generally doesn't use the Regex config rules, but we pass them to satisfy the signature.
        let config = RedactionConfig::default();
        let options = EngineOptions::default();

        let result = headless_sanitize_string(
            config,
            options,
            content,
            "test_entropy",
            HeadlessEngineType::Entropy
        );

        assert!(result.is_ok());
        Ok(())
    }
}
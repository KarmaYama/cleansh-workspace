// cleansh/tests/sanitize_shell_integration_tests.rs
//! Integration tests for the "Heat-Seeker" (Entropy) Engine.
//! Verifies that structural data is preserved while high-entropy secrets are removed.

use anyhow::Result;
use cleansh_core::{
    EntropyEngine, 
    SanitizationEngine, 
    config::RedactionConfig
};

#[test]
fn test_heat_seeker_surgical_extraction() -> Result<()> {
    // 1. Configure Engine
    let mut config = RedactionConfig::load_default_rules()?;
    
    // FIX: Set threshold extremely low (0.1) for this test.
    // Goal: We are testing the *Surgical Extraction* logic (the regex/index slicing),
    // not the detection sensitivity. We want to FORCE the engine to detect this
    // so we can prove it cuts the string correctly without eating the timestamp.
    config.engines.entropy.threshold = Some(0.1); 
    
    let engine = EntropyEngine::new(config)?;

    // 2. Input: A log line with a high-entropy API key
    let input = "2025-10-20 [DEBUG] key=Af9!xK3#mP5zQ9@wL1_custom_suffix";
    
    // 3. Run Sanitization
    let (output, _) = engine.sanitize(input, "test", "v1", "s1", "u1", "manual", "p1", None)?;

    // 4. Assertions
    // Ensure the "natural language" structure (timestamp, key name) is preserved
    assert!(output.contains("2025-10-20 [DEBUG] key="), 
        "Natural language/structure was damaged: {}", output);

    // Ensure the secret payload is definitely gone
    assert!(!output.contains("Af9!xK3#mP5"), "Secret leaked! Output: {}", output);

    // Ensure the placeholder was inserted
    assert!(output.contains("[ENTROPY_REDACTED]"), "Redaction placeholder missing");

    Ok(())
}

#[test]
fn test_heat_seeker_preserves_delimiters() -> Result<()> {
    let config = RedactionConfig::load_default_rules()?;
    
    let engine = EntropyEngine::new(config)?;

    // Input: A GitHub token (ghp_ + 36 random chars) inside quotes
    let input = r#"export GITHUB_TOKEN="ghp_1A2b3C4d5E6f7G8h9I0jK1l2M3n4O5p6Q7r8""#;
    
    let (output, _) = engine.sanitize(input, "test", "v1", "s1", "u1", "manual", "p1", None)?;

    // Assert 1: The variable name and opening quote must be preserved
    assert!(output.contains(r#"export GITHUB_TOKEN=""#), "Variable structure broken: {}", output);

    // Assert 2: The Secret part must be gone
    assert!(!output.contains("1A2b3C4d5E6f7"), "Token secret part leaked!");

    // Assert 3: The Smart Redaction check
    assert!(output.contains("[ENTROPY_REDACTED]"));

    // Check that the closing quote still exists at the end of the value
    assert!(output.trim().ends_with(r#"""#) || output.contains(r#"[ENTROPY_REDACTED]""#), 
        "Closing delimiter was destroyed: {}", output);

    Ok(())
}
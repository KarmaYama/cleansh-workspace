// cleansh-core/tests/entropy_config_test.rs
use anyhow::Result;
use cleansh_core::config::RedactionConfig;
use cleansh_core::engines::entropy_engine::EntropyEngine;
use cleansh_core::engine::SanitizationEngine;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_entropy_engine_loads_threshold_from_config() -> Result<()> {
    // 1. Create a config with a reasonable threshold (0.5)
    let yaml_content = r#"
rules: []
engines:
  entropy:
    threshold: 0.5
"#;
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml_content.as_bytes())?;
    
    let config = RedactionConfig::load_from_file(file.path())?;
    
    // Verify config struct was populated correctly
    assert_eq!(config.engines.entropy.threshold, Some(0.5));

    // 2. Initialize engine with this config
    let engine = EntropyEngine::new(config)?;
    
    // 3. Test data with a secret AND enough context for Z-score calculation.
    // The engine needs "boring" text to establish a baseline entropy (mean/std-dev).
    // If the string is too short, Z-score is 0.0.
    let input = "
        [INFO] 2025-10-20 10:00:00 Service started successfully.
        [INFO] 2025-10-20 10:00:01 Loading configuration modules...
        [INFO] 2025-10-20 10:00:02 Database connection established.
        [DEBUG] AUTH_TOKEN=7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c
        [INFO] 2025-10-20 10:00:03 Request processed in 45ms.
        [INFO] 2025-10-20 10:00:04 Cache refreshed.
    ";

    let (sanitized, matches) = engine.sanitize(
        input, 
        "test_source", 
        "run1", 
        "hash1", 
        "user1", 
        "manual", 
        "success", 
        None
    )?;

    // 4. Assert that it WAS caught
    // The hex string is high entropy, and 'AUTH_TOKEN' provides keyword context.
    assert!(sanitized.contains("[ENTROPY_REDACTED]"), "Failed to redact secret from: {}", sanitized);
    assert!(!matches.is_empty());
    
    Ok(())
}

#[test]
fn test_entropy_engine_respects_high_threshold() -> Result<()> {
    // 1. Create a config with an impossibly high threshold (5.0)
    let yaml_content = r#"
rules: []
engines:
  entropy:
    threshold: 5.0
"#;
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml_content.as_bytes())?;
    
    let config = RedactionConfig::load_from_file(file.path())?;
    let engine = EntropyEngine::new(config)?;
    
    // Same input as above
    let input = "
        [INFO] Service started. 
        [DEBUG] AUTH_TOKEN=7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c 
        [INFO] Request processed.
    ";

    let (sanitized, matches) = engine.sanitize(
        input, 
        "test_source", 
        "run1", 
        "hash1", 
        "user1", 
        "manual", 
        "success", 
        None
    )?;

    // 2. Assert that it WAS NOT caught (original string remains)
    assert_eq!(sanitized, input);
    assert!(matches.is_empty());
    
    Ok(())
}
// cleansh-core/tests/profile_tests.rs
use cleansh_core::profiles::*;
use anyhow::Result;

// Correctly import RedactionConfig and RedactionRule from the cleansh-core crate
use cleansh_core::config::{RedactionConfig, RedactionRule};

#[test]
fn test_profile_validation_success() -> Result<()> {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("email".to_string()),
                replace_with: "".to_string(),
                description: None,
                multiline: false,
                dot_matches_new_line: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: None,
                tags: None,
                opt_in: false,
            },
            RedactionRule {
                name: "credit_card".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("credit_card".to_string()),
                replace_with: "".to_string(),
                description: None,
                multiline: false,
                dot_matches_new_line: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: None,
                tags: None,
                opt_in: false,
            },
        ],
        engines: Default::default(), // Added
    };

    let profile = ProfileConfig {
        profile_name: "test_profile".to_string(),
        display_name: None,
        description: None,
        version: "v1.0".to_string(),
        profile_id: None,
        author: None,
        compliance_scope: None,
        revision_date: None,
        signature: None,
        signature_alg: None,
        rules: vec![
            ProfileRule { name: "email".to_string(), enabled: Some(false), severity: None },
            ProfileRule { name: "credit_card".to_string(), enabled: Some(true), severity: Some("high".to_string()) },
        ],
        samples: Some(SamplesConfig { max_per_rule: 3, max_total: 10 }),
        dedupe: None,
        post_processing: None,
        reporting: None,
    };

    profile.validate(&default_config)?;
    Ok(())
}

#[test]
fn test_profile_validation_fails_on_unknown_rule() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("email".to_string()),
                replace_with: "".to_string(),
                description: None,
                multiline: false,
                dot_matches_new_line: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: None,
                tags: None,
                opt_in: false,
            },
        ],
        engines: Default::default(), // Added
    };

    let profile = ProfileConfig {
        profile_name: "test_profile".to_string(),
        display_name: None,
        description: None,
        version: "v1.0".to_string(),
        profile_id: None,
        author: None,
        compliance_scope: None,
        revision_date: None,
        signature: None,
        signature_alg: None,
        rules: vec![
            ProfileRule { name: "unknown_rule".to_string(), enabled: Some(true), severity: None },
        ],
        samples: None,
        dedupe: None,
        post_processing: None,
        reporting: None,
    };

    assert!(profile.validate(&default_config).is_err());
}

#[test]
fn test_profile_validation_fails_on_invalid_samples() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("email".to_string()),
                replace_with: "".to_string(),
                description: None,
                multiline: false,
                dot_matches_new_line: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: None,
                tags: None,
                opt_in: false,
            },
        ],
        engines: Default::default(), // Added
    };

    let profile = ProfileConfig {
        profile_name: "test_profile".to_string(),
        display_name: None,
        description: None,
        version: "v1.0".to_string(),
        profile_id: None,
        author: None,
        compliance_scope: None,
        revision_date: None,
        signature: None,
        signature_alg: None,
        rules: vec![
            ProfileRule { name: "email".to_string(), enabled: Some(true), severity: None },
        ],
        samples: Some(SamplesConfig { max_per_rule: 10, max_total: 5 }),
        dedupe: None,
        post_processing: None,
        reporting: None,
    };

    assert!(profile.validate(&default_config).is_err());
}

#[test]
fn test_profile_validation_handles_unlimited_samples() -> Result<()> {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("email".to_string()),
                replace_with: "".to_string(),
                description: None,
                multiline: false,
                dot_matches_new_line: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: None,
                tags: None,
                opt_in: false,
            },
        ],
        engines: Default::default(), // Added
    };

    let profile = ProfileConfig {
        profile_name: "test_profile".to_string(),
        display_name: None,
        description: None,
        version: "v1.0".to_string(),
        profile_id: None,
        author: None,
        compliance_scope: None,
        revision_date: None,
        signature: None,
        signature_alg: None,
        rules: vec![
            ProfileRule { name: "email".to_string(), enabled: Some(true), severity: None },
        ],
        samples: Some(SamplesConfig { max_per_rule: 3, max_total: 0 }),
        dedupe: None,
        post_processing: None,
        reporting: None,
    };

    assert!(profile.validate(&default_config).is_ok());
    Ok(())
}
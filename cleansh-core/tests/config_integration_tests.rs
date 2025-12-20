// cleansh-core/tests/config_integration_tests.rs
use anyhow::Result;
use tempfile::NamedTempFile;
use std::io::Write;

// Import the specific types and functions needed from the main crate's config module
use cleansh_core::config::{self, RedactionConfig, RedactionRule};

#[test]
fn test_load_default_rules() {
    let config = RedactionConfig::load_default_rules().unwrap();
    assert!(!config.rules.is_empty());
    assert!(config.rules.iter().any(|r| r.name == "email"));
    // Check default for programmatic_validation
    let email_rule = config.rules.iter().find(|r| r.name == "email").unwrap();
    assert!(!email_rule.programmatic_validation);
}

#[test]
fn test_load_from_file() -> Result<()> {
    let yaml_content = r#"
rules:
  - name: test_rule
    pattern: "test"
    replace_with: "[TEST]"
    description: "A test rule"
    multiline: false
    dot_matches_new_line: false
    programmatic_validation: true # Explicitly set
    author: "test-author"
    created_at: "2023-01-01T00:00:00Z"
    updated_at: "2023-01-01T00:00:00Z"
    version: "1.0"
"#;
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml_content.as_bytes())?;
    let config = RedactionConfig::load_from_file(file.path())?;
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "test_rule");
    assert!(config.rules[0].programmatic_validation); // Assert true for explicit
    assert_eq!(config.rules[0].pattern, Some("test".to_string()));
    Ok(())
}

#[test]
fn test_load_from_file_programmatic_validation_default() -> Result<()> {
    let yaml_content = r#"
rules:
  - name: another_rule
    pattern: "another"
    replace_with: "[ANOTHER]"
    # programmatic_validation is omitted, so it should default to false
    author: "test-author"
    created_at: "2023-01-01T00:00:00Z"
    updated_at: "2023-01-01T00:00:00Z"
    version: "1.0"
"#;
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml_content.as_bytes())?;
    let config = RedactionConfig::load_from_file(file.path())?;
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "another_rule");
    assert!(!config.rules[0].programmatic_validation); // Assert false for default
    assert_eq!(config.rules[0].pattern, Some("another".to_string()));
    Ok(())
}

#[test]
fn test_merge_rules_no_user_config() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("old@example.com".to_string()),
                replace_with: "[OLD_EMAIL]".to_string(),
                description: Some("old email".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
        ],
        engines: Default::default(), // Added
    };
    let merged = config::merge_rules(default_config.clone(), None);
    assert_eq!(merged.rules.len(), 1);
    assert_eq!(merged.rules[0].name, "email");
    assert_eq!(merged.rules[0].replace_with, "[OLD_EMAIL]");
    assert!(!merged.rules[0].programmatic_validation);
}

#[test]
fn test_merge_rules_override() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("default@example.com".to_string()),
                replace_with: "[DEFAULT_EMAIL]".to_string(),
                description: Some("default email".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
            RedactionRule {
                name: "ipv4_address".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("0.0.0.0".to_string()),
                replace_with: "[DEFAULT_IPV4]".to_string(),
                description: Some("default ipv4".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
        ],
        engines: Default::default(), // Added
    };
    let user_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("user@custom.com".to_string()),
                replace_with: "[CUSTOM_EMAIL]".to_string(),
                description: Some("custom email".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: true,
                enabled: None,
                severity: Some("medium".to_string()),
                tags: Some(vec!["user".to_string()]),
            },
        ],
        engines: Default::default(), // Added
    };
    let merged = config::merge_rules(default_config, Some(user_config));
    assert_eq!(merged.rules.len(), 2);
    let email_rule = merged.rules.iter().find(|r| r.name == "email").unwrap();
    assert_eq!(email_rule.replace_with, "[CUSTOM_EMAIL]");
    assert_eq!(email_rule.pattern, Some("user@custom.com".to_string()));
    assert!(email_rule.programmatic_validation);
    let ipv4_rule = merged.rules.iter().find(|r| r.name == "ipv4_address").unwrap();
    assert_eq!(ipv4_rule.replace_with, "[DEFAULT_IPV4]");
    assert!(!ipv4_rule.programmatic_validation);
}

#[test]
fn test_merge_rules_add_new() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("default@example.com".to_string()),
                replace_with: "[DEFAULT_EMAIL]".to_string(),
                description: Some("default email".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
        ],
        engines: Default::default(), // Added
    };
    let user_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "new_rule".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("new_pattern".to_string()),
                replace_with: "[NEW]".to_string(),
                description: Some("new rule".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: true,
                enabled: None,
                severity: None,
                tags: None,
            },
        ],
        engines: Default::default(), // Added
    };
    let merged = config::merge_rules(default_config, Some(user_config));
    assert_eq!(merged.rules.len(), 2);
    assert!(merged.rules.iter().any(|r| r.name == "email"));
    let new_rule = merged.rules.iter().find(|r| r.name == "new_rule").unwrap();
    assert!(new_rule.programmatic_validation);
}

#[test]
fn test_merge_rules_with_opt_in() {
    let default_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "default_opt_in".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("default_opt_in_value".to_string()),
                replace_with: "[DEFAULT_OPT_IN]".to_string(),
                description: Some("default opt-in rule".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: true,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
            RedactionRule {
                name: "default_non_opt_in".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("default_non_opt_in_value".to_string()),
                replace_with: "[DEFAULT_NON_OPT_IN]".to_string(),
                description: Some("default non-opt-in rule".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: None,
            },
        ],
        engines: Default::default(), // Added
    };
    let user_config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "user_opt_in".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("user_opt_in_value".to_string()),
                replace_with: "[USER_OPT_IN]".to_string(),
                description: Some("user opt-in rule".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: true,
                programmatic_validation: false,
                enabled: None,
                severity: None,
                tags: Some(vec!["user".to_string()]),
            },
            RedactionRule {
                name: "default_opt_in".to_string(),
                author: "".to_string(),
                created_at: "".to_string(),
                updated_at: "".to_string(),
                version: "".to_string(),
                pattern_type: "regex".to_string(),
                pattern: Some("overridden_default_opt_in_value".to_string()),
                replace_with: "[OVERRIDDEN_DEFAULT_OPT_IN]".to_string(),
                description: Some("overridden default opt-in rule".to_string()),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: true,
                enabled: Some(true),
                severity: Some("high".to_string()),
                tags: Some(vec!["user".to_string()]),
            },
        ],
        engines: Default::default(), // Added
    };
    let merged = config::merge_rules(default_config, Some(user_config));
    assert_eq!(merged.rules.len(), 3);

    let default_opt_in_rule = merged.rules.iter().find(|r| r.name == "default_opt_in").unwrap();
    assert_eq!(default_opt_in_rule.replace_with, "[OVERRIDDEN_DEFAULT_OPT_IN]");
    assert_eq!(default_opt_in_rule.pattern, Some("overridden_default_opt_in_value".to_string()));
    assert!(!default_opt_in_rule.opt_in);
    assert!(default_opt_in_rule.programmatic_validation);

    assert!(merged.rules.iter().any(|r| r.name == "user_opt_in"));
    assert!(merged.rules.iter().any(|r| r.name == "default_non_opt_in"));
}
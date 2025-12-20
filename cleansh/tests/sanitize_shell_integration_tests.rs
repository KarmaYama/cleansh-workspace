// cleansh/tests/sanitize_shell_integration_tests.rs
//! Integration tests for the sanitization engine using shell-like scenarios.

use anyhow::Result;
use cleansh_core::config::{RedactionConfig, RedactionRule, MAX_PATTERN_LENGTH};
use cleansh_core::{engine::SanitizationEngine, RegexEngine};
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};

#[allow(unused_imports)]
#[cfg(test)]
mod test_setup {
    use std::sync::Once;
    static INIT: Once = Once::new();

    pub fn setup_logger() {
        INIT.call_once(|| {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .is_test(true)
                .try_init()
                .ok(); 
        });
    }
}

fn create_test_rule(
    name: &str,
    pattern: &str,
    replace: &str,
    opt_in: bool,
    description: Option<&str>,
    multiline: bool,
    dot_matches_new_line: bool,
    programmatic_validation: bool,
) -> RedactionRule {
    RedactionRule {
        name: name.to_string(),
        author: "test_author".to_string(),
        version: "1.0.0".to_string(),
        created_at: Utc::now().to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
        pattern: Some(pattern.to_string()),
        pattern_type: "regex".to_string(),
        replace_with: replace.to_string(),
        description: description.map(|s| s.to_string()),
        multiline,
        dot_matches_new_line,
        opt_in,
        programmatic_validation,
        enabled: Some(true),
        severity: Some("low".to_string()),
        tags: Some(vec!["test".to_string()]),
    }
}

fn filter_rules(
    rules: Vec<RedactionRule>,
    enabled: &[String],
    disabled: &[String],
) -> Vec<RedactionRule> {
    rules.into_iter().filter(|r| {
        let is_enabled_explicitly = enabled.contains(&r.name);
        let is_disabled_explicitly = disabled.contains(&r.name);

        if is_disabled_explicitly {
            false
        } else if r.opt_in {
            is_enabled_explicitly
        } else {
            true 
        }
    }).collect()
}

#[test]
fn test_compile_rules_basic() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false),
        create_test_rule("ip", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", false, None, false, false, false),
    ];
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: rules_vec, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 2);
    Ok(())
}

#[test]
fn test_compile_rules_opt_in_not_enabled() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false),
        create_test_rule("aws_key", "AKIA[A-Z0-9]{16}", "[AWS_KEY]", true, None, false, false, false),
    ];
    let filtered_rules = filter_rules(rules_vec, &[], &[]);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: filtered_rules, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 1);
    assert_eq!(engine.get_rules().rules[0].name, "email");
    Ok(())
}

#[test]
fn test_compile_rules_opt_in_missing_returns_empty() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("secret_key", r"secret_\w+", "[REDACTED]", true, None, false, false, false),
    ];
    let filtered_rules = filter_rules(rules_vec, &[], &[]);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: filtered_rules, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 0);
    Ok(())
}

#[test]
fn test_compile_rules_opt_in_enabled() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false),
        create_test_rule("aws_key", "AKIA[A-Z0-9]{16}", "[AWS_KEY]", true, None, false, false, false),
    ];
    let filtered_rules = filter_rules(rules_vec, &["aws_key".to_string()], &[]);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: filtered_rules, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 2);
    assert!(engine.get_rules().rules.iter().any(|r| r.name == "aws_key"));
    Ok(())
}

#[test]
fn test_compile_rules_disabled() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false),
        create_test_rule("aws_key", "AKIA[A-Z0-9]{16}", "[AWS_KEY]", true, None, false, false, false),
    ];
    let filtered_rules = filter_rules(rules_vec, &["aws_key".to_string()], &["email".to_string()]);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: filtered_rules, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 1);
    assert_eq!(engine.get_rules().rules[0].name, "aws_key");
    Ok(())
}

#[test]
fn test_compile_rules_opt_in_and_disabled_conflict() -> Result<()> {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("sensitive_data", "sensitive_text", "[REDACTED]", true, None, false, false, false),
    ];
    let filtered_rules = filter_rules(rules_vec, &["sensitive_data".to_string()], &["sensitive_data".to_string()]);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: filtered_rules, engines: Default::default() };
    let engine = RegexEngine::new(config)?;
    assert_eq!(engine.get_rules().rules.len(), 0);
    Ok(())
}

#[test]
fn test_overlapping_rules_priority() -> Result<()> {
    test_setup::setup_logger();
    let rule_email = create_test_rule("email", r"(\w+)@example\.com", "[EMAIL]", false, None, false, false, false);
    let rule_generic = create_test_rule("example_match", r"example\.com", "[DOMAIN]", false, None, false, false, false);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule_email, rule_generic], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "user@example.com";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (sanitized, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized, "[EMAIL]");
    Ok(())
}

#[test]
fn test_sanitize_content_basic() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL_REDACTED]", false, None, false, false, false);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "My email is test@example.com.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (output, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(output, "My email is [EMAIL_REDACTED].");
    Ok(())
}

#[test]
fn test_sanitize_content_multiple_matches_same_rule() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL_REDACTED]", false, None, false, false, false);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "test1@example.com and test2@example.com.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (output, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(
        output,
        "[EMAIL_REDACTED] and [EMAIL_REDACTED]."
    );
    Ok(())
}

#[test]
fn test_sanitize_content_multiple_rules() -> Result<()> {
    test_setup::setup_logger();
    let email_rule = create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false);
    let ip_rule = create_test_rule("ipv4_address", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IPV4]", false, None, false, false, false);

    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![email_rule, ip_rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "Email: a@b.com, IP: 192.168.1.1.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (output, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(output, "Email: [EMAIL], IP: [IPV4].");
    Ok(())
}

#[test]
fn test_sanitize_content_with_ansi_escapes() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", false, None, false, false, false);
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input_with_ansi = "Hello \x1b[31mtest@example.com\x1b[0m world.";
    let input_stripped = strip_ansi_escapes::strip_str(input_with_ansi);
    
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input_stripped.as_bytes()));
    let (output, _summary) = engine.sanitize(&input_stripped, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(output, "Hello [EMAIL] world.");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_valid() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_valid = "My SSN is 123-45-6789. Another is 789-12-3456.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_valid.as_bytes()));
    let (sanitized_valid, _summary) = engine.sanitize(text_valid, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;

    assert_eq!(sanitized_valid, "My SSN is [US_SSN_REDACTED]. Another is [US_SSN_REDACTED].");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_invalid_area_000() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_invalid_area_000 = "Invalid SSN: 000-12-3456.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_invalid_area_000.as_bytes()));
    let (sanitized_invalid_area_000, _summary) = engine.sanitize(text_invalid_area_000, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized_invalid_area_000, "Invalid SSN: 000-12-3456.");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_invalid_area_666() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_invalid_area_666 = "Another invalid: 666-78-9012.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_invalid_area_666.as_bytes()));
    let (sanitized_invalid_area_666, _summary) = engine.sanitize(text_invalid_area_666, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;

    assert_eq!(sanitized_invalid_area_666, "Another invalid: 666-78-9012.");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_invalid_area_9xx() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_invalid_area_9xx = "Area 9: 900-11-2222.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_invalid_area_9xx.as_bytes()));
    let (sanitized_invalid_area_9xx, _summary) = engine.sanitize(text_invalid_area_9xx, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized_invalid_area_9xx, "Area 9: 900-11-2222.");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_invalid_group_00() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_invalid_group_00 = "Group 00: 123-00-4567.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_invalid_group_00.as_bytes()));
    let (sanitized_invalid_group_00, _summary) = engine.sanitize(text_invalid_group_00, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;

    assert_eq!(sanitized_invalid_group_00, "Group 00: 123-00-4567.");
    Ok(())
}

#[test]
fn test_us_ssn_programmatic_validation_invalid_serial_0000() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "us_ssn",
        r"\b(\d{3})-(\d{2})-(\d{4})\b",
        "[US_SSN_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let text_invalid_serial_0000 = "Serial 0000: 123-45-0000.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(text_invalid_serial_0000.as_bytes()));
    let (sanitized_invalid_serial_0000, _summary) = engine.sanitize(text_invalid_serial_0000, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized_invalid_serial_0000, "Serial 0000: 123-45-0000.");
    Ok(())
}

#[test]
fn test_uk_nino_programmatic_validation_valid() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "uk_nino",
        r"\b([A-CEGHJ-NPR-TW-Z]{2})\s?(\d{2})\s?(\d{2})\s?(\d{2})\s?([A-D])\b",
        "[UK_NINO_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "Valid NINO: AB123456A. Valid Spaced NINO: AA 12 34 56 B.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (sanitized, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized, "Valid NINO: [UK_NINO_REDACTED]. Valid Spaced NINO: [UK_NINO_REDACTED].");
    Ok(())
}

#[test]
fn test_uk_nino_programmatic_validation_invalid_prefix() -> Result<()> {
    test_setup::setup_logger();
    let rule = create_test_rule(
        "uk_nino",
        r"\b([A-CEGHJ-NPR-TW-Z]{2})\s?(\d{2})\s?(\d{2})\s?(\d{2})\s?([A-D])\b",
        "[UK_NINO_REDACTED]",
        false, None, false, false,
        true,
    );
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: vec![rule], engines: Default::default() };
    let engine = RegexEngine::new(config)?;

    let input = "Invalid BG: BG123456A. Invalid GB: GB123456B. Invalid ZZ: ZZ123456C. Invalid DF: DF123456A. Invalid QV: QV123456B.";
    let run_id = Uuid::new_v4().to_string();
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let (sanitized, _summary) = engine.sanitize(input, "test_source", &run_id, &input_hash, "test_user", "Integration test", "Success", None)?;
    
    assert_eq!(sanitized, "Invalid BG: BG123456A. Invalid GB: GB123456B. Invalid ZZ: ZZ123456C. Invalid DF: DF123456A. Invalid QV: QV123456B.");
    Ok(())
}

#[test]
fn test_compile_rules_invalid_regex_fails_fast() {
    test_setup::setup_logger();
    let rules_vec = vec![
        create_test_rule("valid_rule", "abc", "[REDACTED]", false, None, false, false, false),
        create_test_rule("invalid_rule", "[", "[ERROR]", false, None, false, false, false),
    ];
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: rules_vec, engines: Default::default() };
    let result = RegexEngine::new(config);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(err_msg.contains("Failed to get or compile redaction rules for RegexEngine"));
}

#[test]
fn test_compile_rules_pattern_too_long_fails_fast() {
    test_setup::setup_logger();
    let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
    let rules_vec = vec![
        create_test_rule("valid_rule", "abc", "[REDACTED]", false, None, false, false, false),
        create_test_rule("long_pattern_rule", &long_pattern, "[TOO_LONG]", false, None, false, false, false),
    ];
    // FIX: Added engines: Default::default()
    let config = RedactionConfig { rules: rules_vec, engines: Default::default() };
    let result = RegexEngine::new(config);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(err_msg.contains("Failed to get or compile redaction rules for RegexEngine"));
}
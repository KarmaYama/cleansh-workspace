// cleansh/tests/cli_integration_tests.rs
//! This file contains command-line interface (CLI) integration tests for the `cleansh` application.
//!
//! Integration tests verify the end-to-end functionality of the `cleansh` application
//! by simulating real-world usage scenarios, including applying redaction rules,
//! handling different output modes (file output, clipboard, diff view), and
//! managing the display of redaction summaries.

use anyhow::{Context, Result};
#[allow(unused_imports)] 
use predicates::prelude::*;
use tempfile::NamedTempFile;
use std::io::Write;
use std::fs;

#[allow(unused_imports)]
use assert_cmd::prelude::*;
use assert_cmd::Command;

// Import the specific `strip` function from `strip_ansi_escapes`
use strip_ansi_escapes::strip as strip_ansi_escapes_fn;

use cleansh::commands::cleansh::{run_cleansh_opts, CleanshOptions};
use cleansh::ui::theme::{self, ThemeEntry};
// FIX: Use cleansh_core and cleansh public modules
use cleansh_core::config::{RedactionConfig, merge_rules, RedactionRule};
use cleansh_core::{
    engine::SanitizationEngine,
    RegexEngine,
};
use chrono::Utc;

/// This module ensures that logging (e.g., from `pii_debug!` macro) is set up for tests.
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

fn get_default_theme_map() -> std::collections::HashMap<ThemeEntry, theme::ThemeStyle> {
    theme::ThemeStyle::default_theme_map()
}

fn create_test_engine(custom_config_path: Option<std::path::PathBuf>) -> Result<Box<dyn SanitizationEngine>> {
    let mut config = RedactionConfig::load_default_rules()
        .context("Failed to load default redaction rules")?;

    if let Some(path) = custom_config_path {
        let user_config = RedactionConfig::load_from_file(&path)
            .context("Failed to load user-defined configuration file")?;
        config = merge_rules(config, Some(user_config));
    }

    let engine = RegexEngine::new(config)?;
    Ok(Box::new(engine))
}

fn run_cleansh_command(input: &str, args: &[&str]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    cmd.env("RUST_LOG", "debug");
    cmd.env("CLEANSH_ALLOW_DEBUG_PII", "true");
    cmd.args(args);
    cmd.write_stdin(input.as_bytes()).unwrap();
    cmd.assert()
}

fn strip_ansi(s: &str) -> String {
    let cleaned = strip_ansi_escapes_fn(s);
    String::from_utf8_lossy(&cleaned).to_string()
}

#[test]
fn test_run_cleansh_basic_sanitization() -> Result<()> {
    test_setup::setup_logger();
    let input = "email: test@example.com. My SSN is 123-45-6789.";
    
    // FIX: Added engines: Default::default()
    let config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                description: Some("An email address pattern.".to_string()),
                pattern: Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string()),
                pattern_type: "regex".to_string(),
                replace_with: "[EMAIL]".to_string(),
                author: "test_author".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                version: "1.0.0".to_string(),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: Some("low".to_string()),
                tags: Some(vec!["integration_test".to_string()]),
            },
            RedactionRule {
                name: "us_ssn".to_string(),
                description: Some("A US Social Security Number pattern with programmatic validation.".to_string()),
                pattern: Some(r"\b(\d{3})-(\d{2})-(\d{4})\b".to_string()),
                pattern_type: "regex".to_string(),
                replace_with: "[US_SSN_REDACTED]".to_string(),
                author: "test_author".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                version: "1.0.0".to_string(),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: true,
                enabled: Some(true),
                severity: Some("high".to_string()),
                tags: Some(vec!["integration_test".to_string(), "pii".to_string()]),
            },
        ],
        engines: Default::default(), // Added
    };

    let temp_dir = tempfile::tempdir()?;
    let output_file_path = temp_dir.path().join("output.txt");
    let temp_config_file = temp_dir.path().join("test_rules.yaml");
    let config_yaml = serde_yaml::to_string(&config)?;
    std::fs::write(&temp_config_file, config_yaml)?;

    let engine = create_test_engine(Some(temp_config_file.clone()))?;

    let opts = CleanshOptions {
        input: input.to_string(),
        clipboard: false,
        diff: false,
        output_path: Some(output_file_path.clone()),
        no_redaction_summary: false,
        quiet: false,
    };
    let theme_map = get_default_theme_map();

    run_cleansh_opts(&*engine, opts, &theme_map)?;

    let output_from_file = std::fs::read_to_string(&output_file_path)?;
    let output_stripped_from_file = strip_ansi_escapes::strip_str(&output_from_file);

    assert_eq!(output_stripped_from_file.trim(), "email: [EMAIL]. My SSN is [US_SSN_REDACTED].");

    Ok(())
}

#[test]
fn test_run_cleansh_no_redaction_summary() -> Result<()> {
    test_setup::setup_logger();
    let input = "email: test@example.com. Invalid SSN: 000-12-3456.";
    
    // FIX: Added engines: Default::default()
    let config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                description: Some("An email address pattern.".to_string()),
                pattern: Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string()),
                pattern_type: "regex".to_string(),
                replace_with: "[EMAIL]".to_string(),
                author: "test_author".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                version: "1.0.0".to_string(),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: false,
                enabled: Some(true),
                severity: Some("low".to_string()),
                tags: Some(vec!["integration_test".to_string()]),
            },
            RedactionRule {
                name: "us_ssn".to_string(),
                description: Some("A US Social Security Number pattern with programmatic validation.".to_string()),
                pattern: Some(r"\b(\d{3})-(\d{2})-(\d{4})\b".to_string()),
                pattern_type: "regex".to_string(),
                replace_with: "[US_SSN_REDACTED]".to_string(),
                author: "test_author".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                version: "1.0.0".to_string(),
                multiline: false,
                dot_matches_new_line: false,
                opt_in: false,
                programmatic_validation: true,
                enabled: Some(true),
                severity: Some("high".to_string()),
                tags: Some(vec!["integration_test".to_string(), "pii".to_string()]),
            },
        ],
        engines: Default::default(), // Added
    };

    let temp_dir = tempfile::tempdir()?;
    let output_file_path = temp_dir.path().join("output_no_summary.txt");
    let temp_config_file = temp_dir.path().join("test_rules_no_summary.yaml");
    let config_yaml = serde_yaml::to_string(&config)?;
    std::fs::write(&temp_config_file, config_yaml)?;

    let engine = create_test_engine(Some(temp_config_file.clone()))?;

    let opts = CleanshOptions {
        input: input.to_string(),
        clipboard: false,
        diff: false,
        output_path: Some(output_file_path.clone()),
        no_redaction_summary: true,
        quiet: false,
    };
    let theme_map = get_default_theme_map();

    run_cleansh_opts(&*engine, opts, &theme_map)?;

    let output = std::fs::read_to_string(&output_file_path)?;
    let output_stripped = strip_ansi_escapes::strip_str(&output);

    assert_eq!(output_stripped.trim(), "email: [EMAIL]. Invalid SSN: 000-12-3456.");
    assert!(!output_stripped.contains("--- Redaction Summary ---"));

    Ok(())
}

#[cfg(feature = "clipboard")]
#[test]
fn test_run_cleansh_clipboard_copy() -> Result<()> {
    test_setup::setup_logger();

    if std::env::var("CI").is_ok() {
        eprintln!("Skipping test_run_cleansh_clipboard_copy in CI (no display/X11)");
        return Ok(());
    }

    let input = "email: test@example.com";
    // FIX: Added engines: Default::default()
    let config = RedactionConfig {
        rules: vec![RedactionRule {
            name: "email".to_string(),
            description: Some("An email address pattern.".to_string()),
            pattern: Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string()),
            pattern_type: "regex".to_string(),
            replace_with: "[EMAIL]".to_string(),
            author: "test_author".to_string(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            version: "1.0.0".to_string(),
            multiline: false,
            dot_matches_new_line: false,
            opt_in: false,
            programmatic_validation: false,
            enabled: Some(true),
            severity: Some("low".to_string()),
            tags: Some(vec!["integration_test".to_string()]),
        }],
        engines: Default::default(), // Added
    };

    let temp_dir = tempfile::tempdir()?;
    let output_file_path = temp_dir.path().join("output_clipboard.txt");
    let temp_config_file = temp_dir.path().join("test_rules_clipboard.yaml");
    let config_yaml = serde_yaml::to_string(&config)?;
    std::fs::write(&temp_config_file, config_yaml)?;

    let engine = create_test_engine(Some(temp_config_file.clone()))?;

    let opts = CleanshOptions {
        input: input.to_string(),
        clipboard: true,
        diff: false,
        output_path: Some(output_file_path.clone()),
        no_redaction_summary: true,
        quiet: false,
    };
    let theme_map = get_default_theme_map();

    run_cleansh_opts(&*engine, opts, &theme_map)?;

    let mut clipboard = arboard::Clipboard::new().context("Failed to get clipboard")?;
    let clipboard_content = clipboard.get_text().context("Failed to read clipboard")?;

    assert_eq!(clipboard_content.trim(), "email: [EMAIL]");

    let output_from_file = std::fs::read_to_string(&output_file_path)?;
    let output_stripped_from_file = strip_ansi_escapes::strip_str(&output_from_file);
    assert_eq!(output_stripped_from_file.trim(), "email: [EMAIL]");

    Ok(())
}

#[test]
fn test_run_cleansh_diff_output() -> Result<()> {
    test_setup::setup_logger();
    let input = "Original email: test@example.com\nAnother line.";
    // FIX: Added engines: Default::default()
    let config = RedactionConfig {
        rules: vec![RedactionRule {
            name: "email".to_string(),
            description: Some("An email address pattern.".to_string()),
            pattern: Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string()),
            pattern_type: "regex".to_string(),
            replace_with: "[EMAIL]".to_string(),
            author: "test_author".to_string(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            version: "1.0.0".to_string(),
            multiline: false,
            dot_matches_new_line: false,
            opt_in: false,
            programmatic_validation: false,
            enabled: Some(true),
            severity: Some("low".to_string()),
            tags: Some(vec!["integration_test".to_string()]),
        }],
        engines: Default::default(), // Added
    };

    let temp_dir = tempfile::tempdir()?;
    let output_file_path = temp_dir.path().join("output_diff.txt");
    let temp_config_file = temp_dir.path().join("test_rules_diff.yaml");
    let config_yaml = serde_yaml::to_string(&config)?;
    std::fs::write(&temp_config_file, config_yaml)?;

    let engine = create_test_engine(Some(temp_config_file.clone()))?;

    let opts = CleanshOptions {
        input: input.to_string(),
        clipboard: false,
        diff: true,
        output_path: Some(output_file_path.clone()),
        no_redaction_summary: true,
        quiet: false,
    };
    let theme_map = get_default_theme_map();

    run_cleansh_opts(&*engine, opts, &theme_map)?;

    let output = std::fs::read_to_string(&output_file_path)?;
    let output_stripped = strip_ansi_escapes::strip_str(&output);

    let expected_diff_output_part = vec![
        "-Original email: test@example.com",
        "+Original email: [EMAIL]",
        " Another line.",
    ]
    .join("\n");

    assert!(output_stripped.contains(&expected_diff_output_part), "Expected diff part not found in output:\n'{}'\nActual output:\n'{}'", expected_diff_output_part, output_stripped);
    assert!(!output_stripped.contains("\\n"), "Diff output should not contain literal \\n sequences.");

    assert!(!output_stripped.contains("--- Redaction Summary ---"));

    Ok(())
}

#[test]
fn test_basic_sanitization() -> Result<()> {
    let input = "My email is test@example.com and my IP is 192.168.1.1.";
    let expected_stdout = "My email is [EMAIL_REDACTED] and my IP is [IPV4_REDACTED].\n";
    let expected_stderr_contains_substrings = vec![
        "[DEBUG cleansh_core::config] Loading default rules from embedded string...".to_string(),
        "[DEBUG cleansh_core::sanitizers::compiler] Rule 'email' compiled successfully.".to_string(),
        "[DEBUG cleansh_core::sanitizers::compiler] Rule 'ipv4_address' compiled successfully.".to_string(),
        "Reading input from stdin...".to_string(),
        "[INFO cleansh::commands::cleansh] Starting cleansh operation.".to_string(),
        "Writing sanitized content to stdout.".to_string(),
        "Displaying redaction summary.".to_string(),
        "--- Redaction Summary ---".to_string(),
        "ipv4_address (1 occurrences)".to_string(),
        "email (1 occurrences)".to_string(),
        "[INFO cleansh::commands::cleansh] Cleansh operation completed.".to_string(),
    ];

    let assert_result = run_cleansh_command(input, &["sanitize"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stderr));

    eprint!("\n--- STDOUT Captured ---\n");
    eprintln!("{}", stdout);
    eprintln!("--- END STDOUT ---\n");
    eprint!("\n--- STDERR Captured ---\n");
    eprintln!("{}", stderr);
    eprintln!("--- END STDERR ---\n");

    assert_eq!(stdout, expected_stdout);

    for msg in expected_stderr_contains_substrings {
        assert!(stderr.contains(&msg), "Stderr missing: '{}'\nFull stderr:\n{}", msg, stderr);
    }

    assert!(
        stderr.contains("[DEBUG cleansh_core::redaction_match] cleansh_core::engine Captured match (original): 'test@example.com' for rule 'email'"),
        "Stderr missing expected original capture log for email.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("[DEBUG cleansh_core::redaction_match] cleansh_core::engine Captured match (original): '192.168.1.1' for rule 'ipv4_address'"),
        "Stderr missing expected original capture log for IP.\nFull stderr:\n{}", stderr
    );
    
    Ok(())
}

#[cfg(feature = "clipboard")]
#[test]
fn test_run_cleansh_clipboard_copy_to_file() -> Result<()> {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping clipboard test in CI (no display)");
        return Ok(());
    }

    let input = "My email is test@example.com";
    let expected_file_content = "My email is [EMAIL_REDACTED]\n";
    
    let config_yaml = r#"rules:
  - name: "email"
    pattern: "([a-z]+@[a-z]+\\.com)"
    replace_with: "[EMAIL_REDACTED]"
    description: "Email address."
    multiline: false
    dot_matches_new_line: false
    programmatic_validation: false
    opt_in: false
"#;
    let mut config_file = NamedTempFile::new()?;
    config_file.write_all(config_yaml.as_bytes())?;
    let config_path = config_file.path().to_str().unwrap();

    let output_file = NamedTempFile::new()?;
    let output_path = output_file.path().to_str().unwrap();

    let assert_result = run_cleansh_command(input, &[
        "sanitize", 
        "-c", 
        "-o", output_path, 
        "--config", config_path, 
        "--no-redaction-summary", 
    ]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stderr));

    eprint!("\n--- STDOUT Captured ---\n");
    eprintln!("{}", stdout);
    eprintln!("--- END STDOUT ---\n");
    eprint!("\n--- STDERR Captured ---\n");
    eprintln!("{}", stderr);
    eprintln!("--- END STDERR ---\n");

    assert_eq!(stdout, "");

    assert!(
        stderr.contains("Reading input from stdin..."),
        "Stderr missing `Reading input` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("[INFO cleansh::commands::cleansh] Starting cleansh operation."),
        "Stderr missing `Starting cleansh operation` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("Writing sanitized content to file:"),
        "Stderr missing `Writing sanitized content to file:` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains(&format!("[DEBUG cleansh::commands::cleansh] [cleansh::commands::cleansh] Outputting to file: {}", output_path)),
        "Stderr missing `Outputting to file:` log with path.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("Sanitized content copied to clipboard successfully."),
        "Stderr missing `Sanitized content copied to clipboard` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("[DEBUG cleansh_core::redaction_match] cleansh_core::engine Captured match (original): 'test@example.com' for rule 'email'"),
        "Stderr missing `Captured match (original)` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("[INFO cleansh::commands::cleansh] Cleansh operation completed."),
        "Stderr missing `Cleansh operation completed` log.\nFull stderr:\n{}", stderr
    );

    let file_contents = fs::read_to_string(output_path)?;
    assert_eq!(file_contents, expected_file_content);

    Ok(())
}

#[cfg(feature = "clipboard")]
#[test]
fn test_clipboard_output_with_jwt() -> Result<()> {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping clipboard test in CI (no display)");
        return Ok(());
    }

    let input = "Secret JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let expected_stdout = "Secret JWT: [JWT_REDACTED]\n";

    let expected_stderr_contains_substrings = vec![
        "Reading input from stdin...".to_string(),
        "Sanitized content copied to clipboard successfully.".to_string(),
        "[INFO cleansh::commands::cleansh] Starting cleansh operation.".to_string(),
        "[DEBUG cleansh_core::config] Loading default rules from embedded string...".to_string(),
        "[DEBUG cleansh_core::sanitizers::compiler] Rule 'jwt_token' compiled successfully.".to_string(),
        "[DEBUG cleansh_core::redaction_match] cleansh_core::engine Captured match (original): 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' for rule 'jwt_token'".to_string(),
        "[INFO cleansh::commands::cleansh] Cleansh operation completed.".to_string(),
    ];

    let assert_result = run_cleansh_command(input, &["sanitize", "--clipboard", "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stderr));

    eprint!("\n--- STDOUT Captured ---\n");
    eprintln!("{}", stdout);
    eprintln!("--- END STDOUT ---\n");
    eprint!("\n--- STDERR Captured ---\n");
    eprintln!("{}", stderr);
    eprintln!("--- END STDERR ---\n");

    assert_eq!(stdout, expected_stdout);
    for msg in expected_stderr_contains_substrings {
        assert!(stderr.contains(&msg), "Stderr missing: '{}'\nFull stderr:\n{}", msg, stderr);
    }

    Ok(())
}

#[test]
fn test_diff_view() -> Result<()> {
    let input = "Old IP: 10.0.0.1. New IP: 192.168.1.1.";
    let assert_result = run_cleansh_command(input, &["sanitize", "--diff", "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    assert!(stdout.contains("-Old IP: 10.0.0.1. New IP: 192.168.1.1.\n"));
    assert!(stdout.contains("+Old IP: [IPV4_REDACTED]. New IP: [IPV4_REDACTED].\n"));
    Ok(())
}

#[test]
fn test_output_to_file() -> Result<()> {
    let file = NamedTempFile::new()?;
    let file_path = file.path().to_owned();
    let file_path_str = file_path.to_str().unwrap();

    let input = "This is a test with sensitive info: user@domain.com";

    let assert_result = run_cleansh_command(input, &["sanitize", "-o", file_path_str, "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));

    assert_eq!(stdout, "");

    let content = fs::read_to_string(&file_path)?;
    assert_eq!(content, "This is a test with sensitive info: [EMAIL_REDACTED]\n");

    Ok(())
}

#[test]
fn test_custom_config_file() -> Result<()> {
    let mut config_file = NamedTempFile::new()?;
    let config_content = r#"
rules:
  - name: "my_secret_token"
    pattern: "MYSECRET-\\d{4}"
    replace_with: "[SECRET_TOKEN]"
    opt_in: false
    description: "A secret token for testing"
    multiline: false
    dot_matches_new_line: false
  - name: "email"
    pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
    replace_with: "[EMAIL_REDACTED]"
    opt_in: false
    description: "Email Address"
    multiline: false
    dot_matches_new_line: false
"#;
    config_file.write_all(config_content.as_bytes())?;
    let config_path = config_file.path().to_str().unwrap();

    let original_text =
        "My email is user@example.com and another is user@test.org. My secret is MYSECRET-1234.";

    let assert_result = run_cleansh_command(original_text, &["sanitize", "--config", config_path, "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));

    assert_eq!(stdout, "My email is [EMAIL_REDACTED] and another is [EMAIL_REDACTED]. My secret is [SECRET_TOKEN].\n");

    Ok(())
}
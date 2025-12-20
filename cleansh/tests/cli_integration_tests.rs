// cleansh/tests/cli_integration_tests.rs
//! This file contains command-line interface (CLI) integration tests for the `cleansh` application.
//!
//! These tests focus on verifying the `cleansh` executable's behavior when invoked from the command line,
//! simulating real user interactions. They cover various scenarios including:
//! - Basic sanitization with default rules.
//! - Output redirection to files.
//! - Clipboard integration (when the feature is enabled).
//! - Diff view output.
//! - Loading and merging custom redaction rules from a configuration file.
//!
//! The tests use `assert_cmd` to execute the `cleansh` binary and capture its `stdout` and `stderr`.
//! `tempfile` is used for creating temporary input/output files and configuration files,
//! ensuring tests are isolated and leave no artifacts.
//! `strip_ansi_escapes` is crucial for reliable assertions against console output,
//! as `cleansh` may produce colored (ANSI escaped) output which needs to be stripped
//! for plain text comparison.
//!
//! Logging: `RUST_LOG` and `CLEANSH_ALLOW_DEBUG_PII` environment variables are set
//! for the spawned `cleansh` process to enable detailed debug logging and
//! reveal original PII in logs for testing purposes, allowing comprehensive
//! verification of internal logic and data flow.

use anyhow::Result;
#[allow(unused_imports)] // This is often used by `predicates::str::contains`
use predicates::prelude::*;
use tempfile::NamedTempFile;
use std::io::Write;
use std::fs;

#[allow(unused_imports)] // Used for `Command::cargo_bin` and `assert` method
use assert_cmd::prelude::*;
use assert_cmd::Command;

// Import the specific `strip` function from `strip_ansi_escapes`
use strip_ansi_escapes::strip as strip_ansi_escapes_fn;

/// Helper function to run the `cleansh` command with given input and arguments.
///
/// This function sets up the `Command` to execute the `cleansh` binary,
/// configures environment variables for logging, provides the input via stdin,
/// and returns an `assert_cmd::assert::Assert` object for making assertions
/// on the command's output and exit status.
///
/// # Arguments
/// * `input` - The string input to be fed to `cleansh` via stdin.
/// * `args` - A slice of string slices representing the command-line arguments
///            to pass to `cleansh`.
///
/// # Returns
/// An `assert_cmd::assert::Assert` instance, allowing chaining of assertions.
fn run_cleansh_command(input: &str, args: &[&str]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("cleansh").unwrap();
    // CRITICAL: Set RUST_LOG for the *spawned cleansh process*.
    // This ensures debug logs from your application are visible in the test output.
    cmd.env("RUST_LOG", "debug");
    // Allow PII debug logs for testing purposes.
    // Setting this to "true" means the "Rule '{}' captured match (original): {}" log
    // will display the *original*, unredacted PII. This is crucial for verifying
    // that the correct original values are being processed internally.
    cmd.env("CLEANSH_ALLOW_DEBUG_PII", "true");
    cmd.args(args);
    cmd.write_stdin(input.as_bytes()).unwrap();
    cmd.assert()
}

/// Helper function to strip ANSI escape codes from a string.
///
/// `cleansh` can output colored text using ANSI escape codes. For robust string
/// comparisons in assertions, these codes must be removed.
///
/// # Arguments
/// * `s` - The input string, potentially containing ANSI escape codes.
///
/// # Returns
/// A new `String` with all ANSI escape codes removed.
fn strip_ansi(s: &str) -> String {
    let cleaned = strip_ansi_escapes_fn(s);
    String::from_utf8_lossy(&cleaned).to_string()
}

/// Tests basic sanitization functionality of `cleansh` via the CLI.
///
/// This test verifies that `cleansh` can process input from stdin, apply
/// default redaction rules (email and IPv4 address), print the sanitized
/// output to stdout, and output detailed debug logs and a redaction summary
/// to stderr.
///
/// # Test Steps:
/// 1. Define `input` string with an email and an IP address.
/// 2. Define `expected_stdout` (sanitized content) and a list of
///    `expected_stderr_contains_substrings` for log verification.
/// 3. Execute `cleansh` via `run_cleansh_command`. The `--no-clipboard` flag has been removed.
/// 4. Capture and strip ANSI codes from both stdout and stderr.
/// 5. Print captured stdout and stderr for debugging in case of test failure.
/// 6. Assert that stdout exactly matches `expected_stdout`.
/// 7. Assert that stderr contains all expected log messages, including
///    specific debug logs for rule compilation, captured matches, redaction actions,
///    and the redaction summary. This confirms internal processing and logging.
///
/// # Returns
/// `Ok(())` if the test passes, `Err` if any assertion fails.
#[test]
fn test_basic_sanitization() -> Result<()> {
    let input = "My email is test@example.com and my IP is 192.168.1.1.";
    // FIX APPLIED HERE: Added '\n' to the end of the expected_stdout string
    // to match the behavior of `println!` which adds a newline by default.
    let expected_stdout = "My email is [EMAIL_REDACTED] and my IP is [IPV4_REDACTED].\n";
    let expected_stderr_contains_substrings = vec![
        // FIX: Updated version to 0.1.9
        "[INFO cleansh] cleansh started. Version: 0.1.9".to_string(),
        "[DEBUG cleansh_core::config] Loading default rules from embedded string...".to_string(),
        // FIX: The log message has been updated to be more specific.
        "[DEBUG cleansh_core::sanitizers::compiler] Rule 'email' compiled successfully.".to_string(),
        "[DEBUG cleansh_core::sanitizers::compiler] Rule 'ipv4_address' compiled successfully.".to_string(),
        "Reading input from stdin...".to_string(),
        // FIX APPLIED HERE: The log message has changed from "Starting sanitize operation." to "Starting cleansh operation."
        "[INFO cleansh::commands::cleansh] Starting cleansh operation.".to_string(),
        "Writing sanitized content to stdout.".to_string(),
        "Displaying redaction summary.".to_string(),
        "--- Redaction Summary ---".to_string(),
        "ipv4_address (1 occurrences)".to_string(),
        "email (1 occurrences)".to_string(),
        // FIX APPLIED HERE: The log message has been updated to include "successfully."
        "[INFO cleansh::commands::cleansh] Cleansh operation completed.".to_string(),
    ];

    // FIX APPLIED HERE: The subcommand "sanitize" is now mandatory and has been added.
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

    // Updated assertions to match the new log prefixes from `log_captured_match_debug`
    // and `log_redaction_action_debug` in `src/utils/redaction.rs`, and `log_redaction_match_debug` in `cleansh.rs`.
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

/// Tests `cleansh`'s ability to copy sanitized output to the system clipboard
/// and simultaneously write it to a specified file.
///
/// This test is conditional, running only if the `clipboard` feature is enabled
/// and is skipped in CI environments due to potential lack of a display server.
/// It verifies that `stdout` is empty (as output goes to file/clipboard) and
/// checks specific log messages indicating clipboard and file operations.
///
/// # Pre-conditions:
/// - `clipboard` feature must be enabled (`#[cfg(feature = "clipboard")]`).
/// - The test will be skipped if the `CI` environment variable is set.
///
/// # Test Steps:
/// 1. Skip test if in CI.
/// 2. Define `input`, `expected_stdout` (empty for file output), and
///    `expected_stderr_contains` messages.
/// 3. Create a temporary YAML config file for a custom email rule.
/// 4. Create a temporary output file.
/// 5. Execute `cleansh` with `-c` (clipboard), `-o` (output file),
///    `--config` (custom config), and `--no-redaction-summary`.
/// 6. Capture and strip ANSI codes from both stdout and stderr.
/// 7. Print captured stdout and stderr for debugging.
/// 8. Assert that stdout is empty.
/// 9. Assert that stderr contains specific log messages confirming input source,
///    file writing, clipboard copy, and debug logs for rule compilation and redaction.
/// 10. Assert that the content of the temporary output file matches the expected sanitized output.
///
/// # Returns
/// `Ok(())` if the test passes (or is skipped), `Err` if any assertion fails.
#[cfg(feature = "clipboard")]
#[test]
fn test_run_cleansh_clipboard_copy_to_file() -> Result<()> {
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping clipboard test in CI (no display)");
        return Ok(());
    }

    let input = "My email is test@example.com";
    let expected_file_content = "My email is [EMAIL_REDACTED]\n"; // Expected content in file, not stdout
    
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
        "sanitize", // ADDED: The mandatory `sanitize` subcommand
        "-c", // Enable clipboard copy
        "-o", output_path, // Specify output file
        "--config", config_path, // Use custom config
        "--no-redaction-summary", // Do not print summary to stderr
    ]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    let stderr = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stderr));

    eprint!("\n--- STDOUT Captured ---\n");
    eprintln!("{}", stdout);
    eprintln!("--- END STDOUT ---\n");
    eprint!("\n--- STDERR Captured ---\n");
    eprintln!("{}", stderr);
    eprintln!("--- END STDERR ---\n");

    // When outputting to a file, stdout should be empty
    assert_eq!(stdout, "");

    // Assertions for the presence of key log messages.
    // The log for writing to the file has changed. It's no longer an INFO message
    // that includes the file path directly. Instead, there's a DEBUG log.
    // FIX: Updated version to 0.1.9
    assert!(
        stderr.contains("[INFO cleansh] cleansh started. Version: 0.1.9"),
        "Stderr missing `cleansh started` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("Reading input from stdin..."),
        "Stderr missing `Reading input` log.\nFull stderr:\n{}", stderr
    );
    assert!(
        stderr.contains("[INFO cleansh::commands::cleansh] Starting cleansh operation."),
        "Stderr missing `Starting cleansh operation` log.\nFull stderr:\n{}", stderr
    );
    // The `Writing sanitized content to file:` log is now just a string, not a full INFO log
    assert!(
        stderr.contains("Writing sanitized content to file:"),
        "Stderr missing `Writing sanitized content to file:` log.\nFull stderr:\n{}", stderr
    );
    // The debug log now contains the full path
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

/// Tests `cleansh`'s ability to redact JWT tokens and copy the sanitized output
/// to the system clipboard while printing it to stdout.
///
/// This test is conditional, running only if the `clipboard` feature is enabled
/// and is skipped in CI environments due to potential lack of a display server.
/// It focuses on JWT redaction and combined
/// clipboard/stdout output.
///
/// # Pre-conditions:
/// - `clipboard` feature must be enabled (`#[cfg(feature = "clipboard")]`).
/// - The test will be skipped if the `CI` environment variable is set.
///
/// # Test Steps:
/// 1. Skip test if in CI.
/// 2. Define `input` with a JWT, `expected_stdout`, and `expected_stderr_contains` messages.
/// 3. Execute `cleansh` with `-c` (clipboard) and `--no-redaction-summary`.
/// 4. Capture and strip ANSI codes from stdout and stderr.
/// 5. Print captured stdout and stderr for debugging.
/// 6. Assert that stdout exactly matches `expected_stdout`.
/// 7. Assert that stderr contains specific log messages, confirming clipboard copy
///    and JWT redaction details, but no redaction summary.
///
/// # Returns
/// `Ok(())` if the test passes (or is skipped), `Err` if any assertion fails.
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

    // FIX APPLIED: Added "sanitize" subcommand
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


/// Tests `cleansh`'s `--diff` functionality.
///
/// This test verifies that `cleansh` can generate a diff-style output
/// highlighting the changes between the original and sanitized content.
/// It uses a temporary input file to read the data.
///
/// # Test Steps:
/// 1. Create a temporary input file with an IP address.
/// 2. Define `expected_stdout_contains` strings for the diff output.
/// 3. Execute `cleansh` with `--diff` and `--no-redaction-summary`.
///    The `--no-clipboard` flag has been removed.
/// 4. Capture and strip ANSI codes from stdout.
/// 5. Assert that stdout contains the expected diff output lines.
///
/// # Returns
/// `Ok(())` if the test passes, `Err` if any assertion fails.
#[test]
fn test_diff_view() -> Result<()> {
    let input = "Old IP: 10.0.0.1. New IP: 192.168.1.1.";
    // FIX APPLIED HERE: Added the `sanitize` subcommand.
    let assert_result = run_cleansh_command(input, &["sanitize", "--diff", "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));
    assert!(stdout.contains("-Old IP: 10.0.0.1. New IP: 192.168.1.1.\n"));
    assert!(stdout.contains("+Old IP: [IPV4_REDACTED]. New IP: [IPV4_REDACTED].\n"));
    Ok(())
}

/// Tests `cleansh`'s file output functionality (`-o`).
///
/// This test verifies that `cleansh` can write its sanitized output to a
/// specified file instead of stdout. It checks that the output file's content
/// is correct and that `stdout` is empty.
///
/// # Test Steps:
/// 1. Create a temporary output file.
/// 2. Define `input` string.
/// 3. Execute `cleansh` with `-o`, specifying the temporary file path.
///    The `--no-clipboard` flag has been removed.
/// 4. Assert that `stdout` is empty and the output file's content is as expected.
///
/// # Returns
/// `Ok(())` if the test passes, `Err` if any assertion fails.
#[test]
fn test_output_to_file() -> Result<()> {
    let file = NamedTempFile::new()?;
    let file_path = file.path().to_owned();
    let file_path_str = file_path.to_str().unwrap();

    let input = "This is a test with sensitive info: user@domain.com";

    // FIX APPLIED HERE: Added the `sanitize` subcommand.
    let assert_result = run_cleansh_command(input, &["sanitize", "-o", file_path_str, "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));

    assert_eq!(stdout, "");

    let content = fs::read_to_string(&file_path)?;
    assert_eq!(content, "This is a test with sensitive info: [EMAIL_REDACTED]\n");

    Ok(())
}

/// Tests `cleansh`'s ability to load and merge custom redaction rules from
/// a configuration file specified via `--config`.
///
/// This test uses a custom rule to redact a fictional secret token in addition
/// to the default `email` rule, verifying that both are applied correctly.
///
/// # Test Steps:
/// 1. Create a temporary YAML config file with a custom rule.
/// 2. Define `original_text` containing both an email and a custom token.
/// 3. Execute `cleansh` with `--config`, pointing to the temporary file.
///    The `--no-clipboard` flag has been removed.
/// 4. Assert that the stdout contains the correctly redacted output for
///    both the email and the custom token.
///
/// # Returns
/// `Ok(())` if the test passes, `Err` if any assertion fails.
#[test]
fn test_custom_config_file() -> Result<()> {
    // 1. Create a temporary config file
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

    // 2. Prepare the input
    let original_text =
        "My email is user@example.com and another is user@test.org. My secret is MYSECRET-1234.";

    // 3. Run the cleansh command with the custom config
    // FIX APPLIED HERE: Added the `sanitize` subcommand.
    let assert_result = run_cleansh_command(original_text, &["sanitize", "--config", config_path, "--no-redaction-summary"]).success();
    let stdout = strip_ansi(&String::from_utf8_lossy(&assert_result.get_output().stdout));

    // 4. Assert the output is as expected
    assert_eq!(stdout, "My email is [EMAIL_REDACTED] and another is [EMAIL_REDACTED]. My secret is [SECRET_TOKEN].\n");

    Ok(())
}
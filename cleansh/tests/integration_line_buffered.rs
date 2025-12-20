// cleansh/tests/integration_line_buffered.rs
//! Integration tests for the --line-buffered mode of Cleansh.
//!
//! These tests focus on verifying the real-time, line-buffered input/output
//! behavior, including interactions with stdin, stdout, and various
//! redaction scenarios.

use assert_cmd::Command;
use assert_cmd::assert::Assert;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

/// Helper function to create a basic config file for testing.
fn create_test_config(dir: &tempfile::TempDir) -> PathBuf {
    let config_path = dir.path().join("cleansh_test_config.yaml");
    let config_content = r#"
rules:
  - name: "test_ip_address"
    pattern: "\\b(?:\\d{1,3}\\.)*\\d{1,3}\\b"
    replace_with: "[IPV4_REDACTED]"
    multiline: false
    dot_matches_new_line: false
    opt_in: false

  - name: "test_secret_key"
    pattern: "SECRET_KEY=[a-zA-Z0-9]+"
    replace_with: "SECRET_KEY=[REDACTED]"
    multiline: false
    dot_matches_new_line: false
    opt_in: false
"#;
    fs::write(&config_path, config_content).unwrap();
    config_path
}

/// Helper to run a command with piped stdin and capture output.
/// This helper now correctly handles global flags and subcommand arguments.
fn run_cleansh_with_stdin(
    input: &str,
    config_path: Option<&PathBuf>,
    global_args: &[&str],
    subcommand_args: &[&str],
) -> Assert {
    // FIX: Using assert_cmd::cargo_bin! to handle custom build directories and avoid deprecation
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    cmd.args(global_args);
    cmd.arg("sanitize").arg("--line-buffered").args(subcommand_args);

    if let Some(path) = config_path {
        cmd.arg("--config").arg(path);
    }
    
    cmd.write_stdin(input)
       .assert()
}

/// Helper to run a command with only arguments, no stdin interaction expected.
fn run_cleansh_with_args_only(args: &[&str]) -> Assert {
    // FIX: Using assert_cmd::cargo_bin! to handle custom build directories and avoid deprecation
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    cmd.args(args)
       .assert()
}

// -----------------------------------------------------------------------------
// Test cases
// -----------------------------------------------------------------------------

#[test]
fn test_line_buffered_basic_sanitization() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    // Test without --quiet flag, expecting full summary in stderr
    let input = "This is an IP: 192.168.1.100\nAnother secret: SECRET_KEY=abc123def\nNo secret here.\n";
    let output_assert = run_cleansh_with_stdin(input, Some(&config_path), &[], &[]);

    output_assert
        .success()
        .stdout(predicate::str::diff("This is an IP: [IPV4_REDACTED]\nAnother secret: SECRET_KEY=[REDACTED]\nNo secret here.\n"))
        .stderr(
            // NOTE: The following line has been changed.
            // We now check for the presence of all required strings in the output, regardless of their order.
            predicate::str::contains("Using line-buffered mode.")
                .and(predicate::str::contains("--- Redaction Summary ---"))
                .and(predicate::str::contains("ipv4_address (1 occurrences)"))
                .and(predicate::str::contains("test_ip_address (1 occurrences)"))
                .and(predicate::str::contains("test_secret_key (1 occurrences)"))
        );

    // Test with --quiet flag, expecting no summary but the line-buffered message
    let output_quiet_assert = run_cleansh_with_stdin("This is an IP: 192.168.1.100\n", Some(&config_path), &["--quiet"], &[]);

    output_quiet_assert
        .success()
        .stdout(predicate::str::diff("This is an IP: [IPV4_REDACTED]\n"))
        .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}

#[test]
fn test_line_buffered_no_match() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let output_assert = run_cleansh_with_stdin(
        "Just a normal line\nAnother normal line\n",
        Some(&config_path),
        &[],
        &[],
    );

    output_assert
        .success()
        .stdout(predicate::str::diff("Just a normal line\nAnother normal line\n"))
        .stderr(predicate::str::contains("No redactions applied."));

    Ok(())
}

#[test]
fn test_line_buffered_empty_input() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let output_assert = run_cleansh_with_stdin("", Some(&config_path), &[], &[]);

    output_assert
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("No redactions applied."));

    Ok(())
}

#[test]
fn test_line_buffered_line_without_newline_at_end() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let output_assert = run_cleansh_with_stdin(
        "Last line with 1.2.3.4 but no newline",
        Some(&config_path),
        &["--quiet"],
        &[],
    );

    output_assert
        .success()
        .stdout(predicate::str::diff("Last line with [IPV4_REDACTED] but no newline\n"))
        .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}

#[test]
fn test_line_buffered_with_multiple_writes_to_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let input = "First line 1.1.1.1\nSecond line SECRET_KEY=xyz\n";
    let output_assert = run_cleansh_with_stdin(input, Some(&config_path), &["--quiet"], &[]);

    output_assert
        .success()
        .stdout(predicate::str::diff("First line [IPV4_REDACTED]\nSecond line SECRET_KEY=[REDACTED]\n"))
        .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}

#[test]
fn test_line_buffered_incompatible_with_diff() -> Result<(), Box<dyn std::error::Error>> {
    run_cleansh_with_args_only(&["sanitize", "--line-buffered", "--diff"])
        .failure()
        .stderr(predicate::str::contains("Error: --line-buffered is incompatible with --diff, --clipboard, and --input-file."));

    Ok(())
}

#[test]
fn test_line_buffered_incompatible_with_clipboard() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "clipboard")]
    {
        run_cleansh_with_args_only(&["sanitize", "--line-buffered", "--clipboard"])
            .failure()
            .stderr(predicate::str::contains("Error: --line-buffered is incompatible with --diff, --clipboard, and --input-file."));
    }
    Ok(())
}

#[test]
fn test_line_buffered_with_out_flag_warns() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let output_file = dir.path().join("output.txt");
    let config_path = create_test_config(&dir);

    run_cleansh_with_stdin(
        "Some data to sanitize\n",
        Some(&config_path),
        &["--quiet"],
        &["--output", output_file.to_str().unwrap()],
    )
    .success()
    .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}

#[test]
fn test_line_buffered_input_file_flag_not_supported() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);
    let input_file = dir.path().join("input.txt");
    fs::write(&input_file, "File content with 172.16.0.10\nAnother line.\n")?;

    run_cleansh_with_args_only(&[
        "--quiet",
        "sanitize",
        "--line-buffered",
        "--input-file",
        input_file.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
    ])
    .failure()
    .stderr(predicate::str::contains("Error: --line-buffered is incompatible with --diff, --clipboard, and --input-file."));

    Ok(())
}

#[test]
fn test_line_buffered_no_redaction_summary() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let output_assert = run_cleansh_with_stdin(
        "Test with 1.2.3.4 and no summary.\n",
        Some(&config_path),
        &["--quiet"], // Corrected: --quiet is a global flag
        &["--no-redaction-summary"], // Corrected: --no-redaction-summary is a subcommand flag
    );

    output_assert
        .success()
        .stdout(predicate::str::diff("Test with [IPV4_REDACTED] and no summary.\n"))
        .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}

#[test]
fn test_line_buffered_multiple_matches_single_line() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config_path = create_test_config(&dir);

    let output_assert = run_cleansh_with_stdin(
        "Sensitive data: 192.168.1.1 and SECRET_KEY=xyz123abc\n",
        Some(&config_path),
        &["--quiet"],
        &[],
    );

    output_assert
        .success()
        .stdout(predicate::str::diff("Sensitive data: [IPV4_REDACTED] and SECRET_KEY=[REDACTED]\n"))
        .stderr(predicate::str::contains("Using line-buffered mode."));

    Ok(())
}
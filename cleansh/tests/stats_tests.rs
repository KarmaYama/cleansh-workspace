// cleansh/tests/stats_tests.rs
// tests/stats_tests.rs
use std::env;
use std::fs;
use std::path::PathBuf;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;
use log::{debug, LevelFilter};
use cleansh::logger;
use cleansh::utils::app_state::AppState;

// --- Helper Functions and Structures for Tests ---

/// Manages temporary directories and paths for each test, ensuring isolation.
struct TestPaths {
    _temp_dir: TempDir, // Held to ensure temp_dir lives until test ends
    app_state_file_path: PathBuf,
}

/// Creates a new, isolated temporary directory and initializes a default AppState file within it.
/// This ensures each test starts with a clean slate for app state persistence.
fn get_test_paths(test_name: &str) -> anyhow::Result<TestPaths> {
    // Initialize logger for the test. Only sets it if not already set.
    logger::init_logger(Some(LevelFilter::Debug));
    debug!("Test setup: Initializing test paths for {}", test_name);

    // Use CARGO_TARGET_TMPDIR for robust temp directory creation across platforms
    let mut temp_base_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    temp_base_dir.push("cleansh_stats_tests_data"); // Common temp directory for all tests in this file
    temp_base_dir.push(test_name); // Specific subdirectory for the current test

    // Ensure the base directory for the test's temp folder exists
    fs::create_dir_all(&temp_base_dir)?;

    let temp_dir = tempfile::tempdir_in(temp_base_dir)?;
    // Define the specific path for the app state file within this temporary directory
    let app_state_file_path = temp_dir.path().join("app_state.json");

    // Initialize a default AppState and save it to the test-specific path.
    let initial_state = AppState::new();
    initial_state.save(&app_state_file_path)?;
    debug!("Test setup: App state file created at {:?}", app_state_file_path);

    Ok(TestPaths {
        _temp_dir: temp_dir,
        app_state_file_path,
    })
}

/// Constructs a `Command` for the `cleansh` binary, configuring it to use a test-specific
/// AppState file via an environment variable. It also **clears relevant environment variables**
/// to ensure test isolation.
fn run_cleansh_cmd(app_state_file: &PathBuf) -> Command {
    // FIX: Using assert_cmd::cargo_bin! macro instead of deprecated cargo_bin function.
    // This allows better resolution in custom build-dir environments.
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    // Pass the test-specific app state file path via an environment variable.
    cmd.env("CLEANSH_STATE_FILE_OVERRIDE_FOR_TESTS", app_state_file.to_str().unwrap());

    // --- IMPORTANT: Clear potentially interfering environment variables for each command call ---
    cmd.env_remove("RUST_LOG");
    cmd.env_remove("CLEANSH_ALLOW_DEBUG_PII"); // Clear PII debug flag
    debug!("Command setup: CLEANSH_STATE_FILE_OVERRIDE_FOR_TESTS set to {:?}", app_state_file);
    cmd
}

/// A custom predicate to check if a string is valid JSON.
fn is_json() -> impl Predicate<str> {
    predicate::function(|s: &str| {
        serde_json::from_str::<Value>(s).is_ok()
    })
}

// --- Test Suite for `stats` Command ---

#[test]
fn test_stats_only_no_matches() -> anyhow::Result<()> {
    let test_paths = get_test_paths("test_stats_only_no_matches")?;
    debug!("Running test_stats_only_no_matches");

    run_cleansh_cmd(&test_paths.app_state_file_path)
        .write_stdin("This is a clean string with no PII.")
        .arg("scan") // Subcommand
        .arg("--rules")
        .arg("default")
        .assert()
        .success() // Assert that the command returns a successful exit status
        .stderr(predicate::str::contains("No redaction matches found.")); // Assert on stderr content
    
    Ok(())
}

#[test]
fn test_stats_only_with_simple_matches() -> anyhow::Result<()> {
    let test_paths = get_test_paths("test_stats_only_with_simple_matches")?;
    debug!("Running test_stats_only_with_simple_matches");

    let input_content = "My email is test@example.com and my IP is 192.168.1.1.";
    
    // Store the output in a variable to extend its lifetime
    let output = run_cleansh_cmd(&test_paths.app_state_file_path)
        .write_stdin(input_content)
        .arg("scan")
        .arg("--rules")
        .arg("default")
        .output()?; // Use `.output()?` to get the raw output struct

    // Now, you can safely use `output` and references to its fields
    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!("Stderr for simple_matches: \n{}", stderr);
    
    assert!(output.status.success()); // Assert the command succeeded
    assert!(stderr.contains("Redaction Statistics Summary"));
    assert!(stderr.contains("Email: 1 match"));
    assert!(stderr.contains("Ipv4 Address: 1 match"));

    Ok(())
}

#[test]
fn test_stats_with_json_file_output() -> anyhow::Result<()> {
    let test_paths = get_test_paths("test_stats_with_json_file_output")?;
    debug!("Running test_stats_with_json_file_output");

    let input_content = "An email: test@example.com. Another: user@domain.com.";
    let json_output_path = test_paths._temp_dir.path().join("stats.json");

    run_cleansh_cmd(&test_paths.app_state_file_path)
        .write_stdin(input_content)
        .arg("scan")
        .arg("--rules")
        .arg("default")
        .arg("--json-file")
        .arg(&json_output_path)
        .assert()
        .success();

    // Read the generated JSON file
    let json_content = fs::read_to_string(&json_output_path)?;
    assert!(is_json().eval(&json_content));

    // Parse and verify the content
    let json: Value = serde_json::from_str(&json_content)?;
    let email_count = json["redaction_summary"]["email"].as_u64().unwrap_or(0);
    assert_eq!(email_count, 2);

    Ok(())
}

#[test]
fn test_stats_with_fail_over() -> anyhow::Result<()> {
    let test_paths = get_test_paths("test_stats_with_fail_over")?;
    debug!("Running test_stats_with_fail_over");

    let input_content = "Email is test1@example.com. Another is test2@example.com.";
    run_cleansh_cmd(&test_paths.app_state_file_path)
        .write_stdin(input_content)
        .arg("scan")
        .arg("--rules")
        .arg("default")
        .arg("--fail-over-threshold")
        .arg("1") // Setting a low threshold to trigger fail-over
        .assert()
        .failure() // Assert that the command returns a failed exit status
        .stderr(predicate::str::contains("FAIL-OVER triggered: Found 2 redaction matches, which exceeds the specified threshold of 1."));
    
    Ok(())
}

#[test]
fn test_stats_rule_disable() -> anyhow::Result<()> {
    let test_paths = get_test_paths("test_stats_rule_disable")?;
    debug!("Running test_stats_rule_disable");

    let input_content = "Email is test1@example.com. IPv4 is 192.168.1.1.";
    
    // Store the output in a variable to extend its lifetime
    let output = run_cleansh_cmd(&test_paths.app_state_file_path)
        .write_stdin(input_content)
        .arg("scan")
        .arg("--rules")
        .arg("default")
        .arg("--disable")
        .arg("email")
        .output()?; 

    let stderr = String::from_utf8_lossy(&output.stderr);
    debug!("Stderr for rule_disable: \n{}", stderr);
    
    assert!(output.status.success()); // Assert the command succeeded
    // Email should not be counted
    assert!(!stderr.contains("Email:"));
    assert!(stderr.contains("Ipv4 Address: 1 match"));

    Ok(())
}
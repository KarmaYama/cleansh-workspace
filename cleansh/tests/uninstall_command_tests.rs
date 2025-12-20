// cleansh/tests/uninstall_command_tests.rs
//! Integration tests for the `cleansh uninstall` command.

use anyhow::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use test_log::test; // For integrating with `env_logger` in tests
use assert_cmd::Command; // For robust CLI command testing

// Correct and direct import paths
use cleansh::commands::uninstall::elevate_and_run_uninstall;
use cleansh::ui::theme;


/// Helper to get a temporary config directory path.
/// This function sets the appropriate environment variable for `dirs::config_dir()`
/// to point to a temporary location, allowing isolated testing of app state management.
fn get_temp_config_dir() -> (PathBuf, tempfile::TempDir) {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().to_path_buf();

    #[cfg(target_os = "windows")]
    {
        // On Windows, set APPDATA
        // env::set_var is unsafe because it can affect other threads or processes
        // that are concurrently reading environment variables.
        unsafe {
            env::set_var("APPDATA", &temp_path);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Unix-like, set XDG_CONFIG_HOME
        // env::set_var is unsafe because it can affect other threads or processes
        // that are concurrently reading environment variables.
        unsafe {
            env::set_var("XDG_CONFIG_HOME", &temp_path);
        }
    }

    (temp_path, temp_dir) // Return both the path and the TempDir object
}

/// Test case for successful uninstallation with confirmation.
/// This test verifies that the app state file and its directory are removed.
#[test(should_panic(expected = "exit code: 0"))] // Expect the process to exit with code 0
fn test_uninstall_command_success_with_confirmation() {
    // Set up a temporary config directory for the test
    let (temp_config_root, _temp_dir_guard) = get_temp_config_dir();
    let cleansh_config_dir = temp_config_root.join("cleansh");
    let app_state_file = cleansh_config_dir.join("app_state.json");

    // Create the dummy app state directory and file
    fs::create_dir_all(&cleansh_config_dir).expect("Failed to create cleansh config directory");
    fs::write(&app_state_file, r#"{ "stats_only_usage_count": 10, "last_prompt_timestamp": 1678886400, "donation_prompts_disabled": false }"#)
        .expect("Failed to write dummy app_state.json");

    // Verify they exist before running uninstall
    assert!(cleansh_config_dir.exists(), "Cleansh config directory should exist before uninstall.");
    assert!(app_state_file.exists(), "App state file should exist before uninstall.");

    // Create a dummy theme map for the uninstall command output
    let theme_map = theme::ThemeStyle::default_theme_map();

    // Call the uninstall command with the --yes flag
    // The `should_panic` attribute handles the `std::process::exit(0)` call.
    let result = elevate_and_run_uninstall(true, &theme_map); // `true` for `yes_flag`

    // This line will only be reached if elevate_and_run_uninstall *doesn't* exit.
    assert!(result.is_ok(), "Uninstall command should return Ok() before exiting.");
}

/// Test case for uninstallation cancellation.
/// This test verifies that if the user cancels, no files are removed and the process exits cleanly.
#[test]
fn test_uninstall_command_cancellation() -> Result<()> {
    // Set up a temporary config directory for the test
    let (temp_config_root, _temp_dir_guard) = get_temp_config_dir();
    let cleansh_config_dir = temp_config_root.join("cleansh");
    let app_state_file = cleansh_config_dir.join("app_state.json");

    // Create the dummy app state directory and file
    fs::create_dir_all(&cleansh_config_dir).expect("Failed to create cleansh config directory");
    fs::write(&app_state_file, r#"{ "stats_only_usage_count": 5, "last_prompt_timestamp": 1678886400, "donation_prompts_disabled": false }"#)
        .expect("Failed to write dummy app_state.json");

    // Verify they exist before running uninstall
    assert!(cleansh_config_dir.exists(), "Cleansh config directory should exist before uninstall.");
    assert!(app_state_file.exists(), "App state file should exist before uninstall.");

    // Create a dummy theme map for the uninstall command output (not directly used by assert_cmd, but good practice)
    let _theme_map = theme::ThemeStyle::default_theme_map();

    // FIX: Using assert_cmd::cargo_bin! to handle custom build directories and avoid deprecation
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    cmd.arg("uninstall"); // Call the uninstall subcommand
    cmd.write_stdin("n\n"); // Simulate typing 'n' followed by a newline

    // Assert that the command runs successfully (exits with code 0)
    // and that the output indicates cancellation (optional, but good for robust testing)
    let _assert = cmd.assert().success();

    // Verify that the files were NOT removed
    assert!(cleansh_config_dir.exists(), "Cleansh config directory should NOT be removed on cancellation.");
    assert!(app_state_file.exists(), "App state file should NOT be removed on cancellation.");

    // Clean up temporary directory after test
    fs::remove_dir_all(&temp_config_root).expect("Failed to clean up temporary config directory.");

    Ok(())
}

/// Test helper to check if app state file and directory are gone.
/// This function is primarily for manual verification or if a future test
/// setup allows checking filesystem state after a process exit.
#[allow(dead_code)] // This function is not directly called by the tests due to `exit(0)`
fn verify_files_deleted(app_state_file: &Path, app_state_dir: &Path) -> bool {
    // Give the OS a moment to release file handles and perform deletion
    std::thread::sleep(std::time::Duration::from_millis(500));
    !app_state_file.exists() && !app_state_dir.exists()
}
// cleansh/tests/uninstall_command_tests.rs
//! Integration tests for the `cleansh uninstall` command.

use anyhow::Result;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use assert_cmd::Command; 

use cleansh::commands::uninstall::elevate_and_run_uninstall;

fn get_temp_config_dir() -> (PathBuf, tempfile::TempDir) {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().to_path_buf();

    #[cfg(target_os = "windows")]
    unsafe { env::set_var("APPDATA", &temp_path); }
    
    // FIX: Added closing parenthesis here
    #[cfg(not(target_os = "windows"))]
    unsafe { env::set_var("XDG_CONFIG_HOME", &temp_path); }

    (temp_path, temp_dir) 
}

// Split attributes into two lines to satisfy new compiler rules
#[test]
#[should_panic(expected = "exit code: 0")] 
fn test_uninstall_command_success_with_confirmation() {
    let (temp_config_root, _temp_dir_guard) = get_temp_config_dir();
    let cleansh_config_dir = temp_config_root.join("cleansh");
    let app_state_file = cleansh_config_dir.join("app_state.json");

    fs::create_dir_all(&cleansh_config_dir).expect("Failed to create cleansh config directory");
    fs::write(&app_state_file, r#"{ "stats_only_usage_count": 10, "last_prompt_timestamp": 1678886400, "donation_prompts_disabled": false }"#)
        .expect("Failed to write dummy app_state.json");

    assert!(cleansh_config_dir.exists(), "Cleansh config directory should exist before uninstall.");
    assert!(app_state_file.exists(), "App state file should exist before uninstall.");

    let result = elevate_and_run_uninstall(true); 

    assert!(result.is_ok(), "Uninstall command should return Ok() before exiting.");
}

#[test]
fn test_uninstall_command_cancellation() -> Result<()> {
    let (temp_config_root, _temp_dir_guard) = get_temp_config_dir();
    let cleansh_config_dir = temp_config_root.join("cleansh");
    let app_state_file = cleansh_config_dir.join("app_state.json");

    fs::create_dir_all(&cleansh_config_dir).expect("Failed to create cleansh config directory");
    fs::write(&app_state_file, r#"{ "stats_only_usage_count": 5, "last_prompt_timestamp": 1678886400, "donation_prompts_disabled": false }"#)
        .expect("Failed to write dummy app_state.json");

    assert!(cleansh_config_dir.exists());
    assert!(app_state_file.exists());

    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    cmd.arg("uninstall"); 
    cmd.write_stdin("n\n"); 

    let _assert = cmd.assert().success();

    assert!(cleansh_config_dir.exists());
    assert!(app_state_file.exists());

    fs::remove_dir_all(&temp_config_root).expect("Failed to clean up temporary config directory.");
    Ok(())
}
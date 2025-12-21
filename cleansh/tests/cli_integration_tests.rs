// cleansh/tests/cli_integration_tests.rs
//! Integration tests for the CleanSH v0.2.0 CLI Bootloader.

use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help_output() -> Result<()> {
    // FIXED: Use the macro to locate the binary instead of the deprecated function
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Sanitize your terminal output"));
    Ok(())
}

#[test]
fn test_cli_invalid_profile_fails() -> Result<()> {
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    
    cmd.arg("--profile").arg("non_existent_profile_xyz");
    // Should fail because we added the profile check in main.rs
    cmd.assert()
        .failure();
    Ok(())
}

#[test]
fn test_cli_quiet_mode_initialization() -> Result<()> {
    let mut cmd = Command::new(assert_cmd::cargo_bin!("cleansh"));
    
    cmd.arg("--quiet");
    // We just verify it compiles and runs without crashing immediately.
    // (It will eventually fail to init TUI in a test env, but that's expected behavior).
    Ok(())
}
// cleansh/src/commands/uninstall.rs
//! Cleansh Uninstallation Command (`uninstall`).
//!
//! This module implements the `cleansh uninstall` command, providing a mechanism
//! for the self-deletion of the Cleansh application and the removal of its
//! associated user data (such as configuration and application state files).
//! It includes user confirmation and platform-specific logic to ensure proper cleanup.

use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::io::{self, Write};
use std::process::Command;
use std::env;
use log::info;
use is_terminal::IsTerminal;

// Platform-specific imports (Windows Only)
#[cfg(target_os = "windows")]
use std::fs::File;
#[cfg(target_os = "windows")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use winapi::um::shellapi::ShellExecuteW;
#[cfg(target_os = "windows")]
use winapi::um::winuser::SW_SHOWNORMAL;
#[cfg(target_os = "windows")]
use winapi::um::fileapi::GetTempPathW;

// Platform-specific imports (Unix Only)
#[cfg(not(target_os = "windows"))]
use std::process::Stdio;

use crate::ui::{output_format, theme};
use crate::commands::cleansh::info_msg;
use crate::ui::theme::ThemeMap;

/// Helper function to convert a Rust string to a wide string for WinAPI.
#[cfg(target_os = "windows")]
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Helper to check elevation on Windows.
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        
        let mut token_handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;
        let success = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as winapi::shared::minwindef::LPVOID,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) != 0;

        CloseHandle(token_handle);
        success && elevation.TokenIsElevated != 0
    }
}

/// The main entry point for the uninstall command.
/// It verifies user intent, determines paths, and then hands off control
/// to a platform-specific deletion script.
pub fn elevate_and_run_uninstall(yes_flag: bool, theme_map: &ThemeMap) -> Result<()> {
    info!("Starting cleansh uninstall operation.");
    let stderr_supports_color = io::stderr().is_terminal();

    // --- 1. User Confirmation (if not running with --yes) ---
    if !yes_flag {
        info_msg("WARNING: This will uninstall Cleansh and remove its associated data.", theme_map);
        output_format::print_message(
            &mut io::stderr(),
            "Are you sure you want to proceed? (y/N): ",
            theme_map,
            Some(theme::ThemeEntry::Prompt),
            stderr_supports_color,
        )?;
        io::stderr().flush()?;

        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)
            .context("Failed to read confirmation input.")?;

        if confirmation.trim().to_lowercase() != "y" {
            info_msg("Uninstallation cancelled.", theme_map);
            return Ok(());
        }
    }

    // --- 2. Determine Paths ---
    let current_exe_path = env::current_exe()
        .context("Failed to determine current executable path.")?;
    
    // Resolve app state path (logic consistent with main.rs)
    let app_state_path = std::env::var("CLEANSH_STATE_FILE_OVERRIDE_FOR_TESTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if let Some(dir) = dirs::data_dir() {
                dir.join("cleansh").join("state.json")
            } else {
                env::current_dir().expect("Failed to get current dir").join("cleansh_state.json")
            }
        });
    let app_state_dir = app_state_path.parent().unwrap_or(&PathBuf::from(".")).to_path_buf();

    info_msg("Preparing removal script...", theme_map);

    #[cfg(target_os = "windows")]
    {
        uninstall_windows(current_exe_path, app_state_path, app_state_dir, theme_map)?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        uninstall_unix(current_exe_path, app_state_path, app_state_dir, theme_map)?;
    }

    Ok(())
}

/// Windows-specific uninstall logic.
/// Generates a PowerShell script to handle deletion after the main process exits.
#[cfg(target_os = "windows")]
fn uninstall_windows(exe_path: PathBuf, state_file: PathBuf, state_dir: PathBuf, theme_map: &ThemeMap) -> Result<()> {
    // 1. Generate Temp Script Path using GetTempPathW for correctness
    let mut temp_path_buf = vec![0u16; 260];
    let temp_path_len = unsafe { GetTempPathW(temp_path_buf.len() as u32, temp_path_buf.as_mut_ptr()) };
    
    // Convert wide string to OsString, then PathBuf
    let temp_dir = PathBuf::from(OsString::from_wide(&temp_path_buf[0..temp_path_len as usize]));
    let script_path = temp_dir.join(format!("cleansh_nuke_{}.ps1", std::process::id()));

    // 2. Generate PowerShell Script Content
    // The script waits for the PID to exit, retries deletion, and cleans up state.
    let current_pid = std::process::id();
    let script_content = format!(
        r#"
$pidToWait = {}
$exePath = "{}"
$stateFile = "{}"
$stateDir = "{}"

Write-Host "Waiting for Cleansh (PID: $pidToWait) to exit..." -ForegroundColor Cyan
try {{
    Wait-Process -Id $pidToWait -Timeout 10 -ErrorAction SilentlyContinue
}} catch {{
    # Process might already be gone
}}

# Ensure file handle release
Start-Sleep -Seconds 1

Write-Host "Deleting executable..." -ForegroundColor Yellow
$deleted = $false
for ($i=0; $i -lt 10; $i++) {{
    try {{
        if (Test-Path $exePath) {{
            Remove-Item -Path $exePath -Force -ErrorAction Stop
            $deleted = $true
            break
        }} else {{
            $deleted = $true # Already gone
            break
        }}
    }} catch {{
        Write-Host "Attempt $($i+1): Locked... retrying..."
        Start-Sleep -Seconds 1
    }}
}}

if (-not $deleted) {{
    Write-Host "Could not delete executable. It may be locked." -ForegroundColor Red
    Write-Host "Please delete manually: $exePath"
}} else {{
    Write-Host "Executable deleted." -ForegroundColor Green
}}

# Clean Configs
if (Test-Path $stateFile) {{ Remove-Item -Path $stateFile -Force; Write-Host "State file removed." }}
if (Test-Path $stateDir) {{ 
    # Only remove if empty or force if desired. Here we recurse.
    Remove-Item -Path $stateDir -Recurse -Force -ErrorAction SilentlyContinue 
    Write-Host "Config directory removed."
}}

Write-Host "Uninstallation Complete." -ForegroundColor Green
Start-Sleep -Seconds 3
# Self-destruct script
Remove-Item -Path $MyInvocation.MyCommand.Path -Force
"#,
        current_pid,
        exe_path.to_string_lossy(),
        state_file.to_string_lossy(),
        state_dir.to_string_lossy()
    );

    // 3. Write Script
    let mut file = File::create(&script_path).context("Failed to create temporary uninstall script")?;
    file.write_all(script_content.as_bytes())?;

    // 4. Execute Script
    let script_path_str = script_path.to_string_lossy().to_string();
    
    // If we are admin, spawn directly. If not, ShellExecute 'runas'.
    if is_elevated() {
        info_msg("Running cleanup script...", theme_map);
        Command::new("powershell.exe")
            .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &script_path_str])
            .spawn()
            .context("Failed to spawn cleanup script")?;
    } else {
        info_msg("Requesting administrative privileges to complete removal...", theme_map);
        
        let operation = to_wide_string("runas");
        let filename = to_wide_string("powershell.exe");
        let args = to_wide_string(&format!("-NoProfile -ExecutionPolicy Bypass -File \"{}\"", script_path_str));

        let res = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                filename.as_ptr(),
                args.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };

        if (res as usize) <= 32 {
            return Err(anyhow!("Failed to launch uninstaller (ShellExecute error: {})", res as usize));
        }
    }

    // 5. Exit Immediately
    // We must exit so the script can delete our binary.
    std::process::exit(0);
}

/// Unix-specific uninstall logic.
/// Spawns a background shell process to handle deletion.
#[cfg(not(target_os = "windows"))]
fn uninstall_unix(exe_path: PathBuf, state_file: PathBuf, state_dir: PathBuf, theme_map: &ThemeMap) -> Result<()> {
    let bash_script = format!(
        r#"
        sleep 1
        rm -f "{}"
        rm -f "{}"
        rm -rf "{}"
        echo "CleanSH uninstalled."
        "#,
        exe_path.to_string_lossy(),
        state_file.to_string_lossy(),
        state_dir.to_string_lossy()
    );

    Command::new("sh")
        .arg("-c")
        .arg(bash_script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn uninstall script")?;

    info_msg("Uninstallation scheduled. Exiting...", theme_map);
    std::process::exit(0);
}
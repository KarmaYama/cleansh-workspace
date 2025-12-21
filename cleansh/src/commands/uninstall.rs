// cleansh/src/commands/uninstall.rs
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::io::{self, Write};
use std::process::Command;
use std::env;
use log::info;

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

#[cfg(not(target_os = "windows"))]
use std::process::Stdio;

#[cfg(target_os = "windows")]
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        let mut token_handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 { return false; }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;
        let success = GetTokenInformation(token_handle, TokenElevation, &mut elevation as *mut _ as winapi::shared::minwindef::LPVOID, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size) != 0;
        CloseHandle(token_handle);
        success && elevation.TokenIsElevated != 0
    }
}

pub fn elevate_and_run_uninstall(yes_flag: bool) -> Result<()> {
    info!("Starting cleansh uninstall operation.");
    if !yes_flag {
        eprintln!("WARNING: This will uninstall Cleansh and remove its associated data.");
        print!("Are you sure you want to proceed? (y/N): ");
        io::stdout().flush()?;
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation).context("Failed to read confirmation input.")?;
        if confirmation.trim().to_lowercase() != "y" { return Ok(()); }
    }
    let current_exe_path = env::current_exe()?;
    let app_state_path = env::var("CLEANSH_STATE_FILE_OVERRIDE_FOR_TESTS").map(PathBuf::from).unwrap_or_else(|_| {
        if let Some(dir) = dirs::data_dir() { dir.join("cleansh").join("state.json") }
        else { env::current_dir().expect("Failed dir").join("cleansh_state.json") }
    });
    let app_state_dir = app_state_path.parent().unwrap_or(&PathBuf::from(".")).to_path_buf();

    #[cfg(target_os = "windows")]
    { uninstall_windows(current_exe_path, app_state_path, app_state_dir)?; }
    #[cfg(not(target_os = "windows"))]
    { uninstall_unix(current_exe_path, app_state_path, app_state_dir)?; }
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows(exe_path: PathBuf, state_file: PathBuf, state_dir: PathBuf) -> Result<()> {
    let mut temp_path_buf = vec![0u16; 260];
    let temp_path_len = unsafe { GetTempPathW(temp_path_buf.len() as u32, temp_path_buf.as_mut_ptr()) };
    let temp_dir = PathBuf::from(OsString::from_wide(&temp_path_buf[0..temp_path_len as usize]));
    let script_path = temp_dir.join(format!("cleansh_nuke_{}.ps1", std::process::id()));
    let script_content = format!(r#"$pidToWait = {}; $exePath = "{}"; $stateFile = "{}"; $stateDir = "{}"; Start-Sleep -Seconds 2; Remove-Item -Path $exePath -Force; Remove-Item -Path $stateFile -Force; Remove-Item -Path $stateDir -Recurse -Force; Remove-Item -Path $MyInvocation.MyCommand.Path -Force"#, std::process::id(), exe_path.to_string_lossy(), state_file.to_string_lossy(), state_dir.to_string_lossy());
    File::create(&script_path)?.write_all(script_content.as_bytes())?;
    let script_path_str = script_path.to_string_lossy().to_string();
    if is_elevated() {
        Command::new("powershell.exe").args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &script_path_str]).spawn()?;
    } else {
        let op = to_wide_string("runas"); let file = to_wide_string("powershell.exe"); let args = to_wide_string(&format!("-NoProfile -ExecutionPolicy Bypass -File \"{}\"", script_path_str));
        unsafe { ShellExecuteW(std::ptr::null_mut(), op.as_ptr(), file.as_ptr(), args.as_ptr(), std::ptr::null(), SW_SHOWNORMAL); }
    }
    std::process::exit(0);
}

#[cfg(not(target_os = "windows"))]
fn uninstall_unix(exe_path: PathBuf, state_file: PathBuf, state_dir: PathBuf) -> Result<()> {
    let bash = format!(r#"sleep 1; rm -f "{}"; rm -f "{}"; rm -rf "{}"; echo "CleanSH uninstalled.""#, exe_path.to_string_lossy(), state_file.to_string_lossy(), state_dir.to_string_lossy());
    Command::new("sh").arg("-c").arg(bash).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    std::process::exit(0);
}
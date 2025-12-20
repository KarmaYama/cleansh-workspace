//! Cleansh command implementation for sanitizing terminal output.

use anyhow::{Context, Result};
// Removed unused 'warn' import
use log::{debug, info};
use std::io::{self, Write};
use std::fs;
// Removed unused 'std::collections::HashMap' import

use cleansh_core::{
    engine::SanitizationEngine,
    RedactionSummaryItem,
};

use crate::ui::diff_viewer;
use crate::ui::redaction_summary;
use crate::ui::output_format;
use crate::ui::theme::{ThemeMap};
use crate::utils::clipboard::copy_to_clipboard;
use is_terminal::IsTerminal;

/// Options for the ergonomic run_cleansh_opts API
pub struct CleanshOptions {
    pub input: String,
    pub clipboard: bool,
    pub diff: bool,
    pub output_path: Option<std::path::PathBuf>,
    pub no_redaction_summary: bool,
    pub quiet: bool,
}

/// Helper for printing info messages to stderr.
pub fn info_msg(msg: impl AsRef<str>, theme: &ThemeMap) {
    let stderr_supports_color = io::stderr().is_terminal();
    let _ = output_format::print_info_message(&mut std::io::stderr(), msg.as_ref(), theme, stderr_supports_color);
}

/// Helper for printing error messages to stderr.
pub fn error_msg(msg: impl AsRef<str>, theme: &ThemeMap) {
    let stderr_supports_color = io::stderr().is_terminal();
    let _ = output_format::print_error_message(&mut std::io::stderr(), msg.as_ref(), theme, stderr_supports_color);
}

/// Helper for printing warning messages to stderr.
pub fn warn_msg(msg: impl AsRef<str>, theme: &ThemeMap) {
    let stderr_supports_color = io::stderr().is_terminal();
    let _ = output_format::print_warn_message(&mut std::io::stderr(), msg.as_ref(), theme, stderr_supports_color);
}

/// The main operation runner for the CleanSH CLI.
pub fn run_cleansh_opts(
    engine: &dyn SanitizationEngine,
    opts: CleanshOptions,
    theme_map: &ThemeMap,
) -> Result<()> {
    info!("Starting cleansh operation.");

    // The core sanitization call. Note: metadata parameters are currently empty
    // but ready for future telemetry/audit-log expansion.
    let (sanitized_content, summary) = engine.sanitize(
        &opts.input,
        "cli-input", // source_id
        "cli-run",   // run_id
        "",          // input_hash
        "local-user",// user_id
        "manual",    // reason
        "success",   // outcome
        None,        // audit_log
    )
    .context("Sanitization failed")?;

    debug!(
        "Content sanitized. Original length: {}, Sanitized length: {}",
        opts.input.len(),
        sanitized_content.len()
    );
    
    // Output handling logic
    handle_primary_output(&opts, &sanitized_content, theme_map)?;

    if opts.clipboard {
        handle_clipboard_output(&sanitized_content, theme_map);
    }
    
    handle_redaction_summary(&summary, &opts, theme_map)?;
    
    info!("Cleansh operation completed.");
    Ok(())
}

fn handle_primary_output(
    opts: &CleanshOptions,
    sanitized_content: &str,
    theme_map: &ThemeMap,
) -> Result<()> {
    if let Some(path) = opts.output_path.clone() {
        info_msg(format!("Writing sanitized content to file: {}", path.display()), theme_map);
        let mut file = fs::File::create(&path)
            .with_context(|| format!("Failed to create output file: {}", path.display()))?;
        
        if opts.diff {
            diff_viewer::print_diff(&opts.input, sanitized_content, &mut file, theme_map, false)?;
        } else {
            writeln!(file, "{}", sanitized_content)?;
        }
    } else {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        let supports_color = stdout.is_terminal();
        
        if opts.diff {
            diff_viewer::print_diff(&opts.input, sanitized_content, &mut writer, theme_map, supports_color)?;
        } else {
            writeln!(writer, "{}", sanitized_content)?;
        }
    };
    Ok(())
}

fn handle_clipboard_output(sanitized_content: &str, theme_map: &ThemeMap) {
    match copy_to_clipboard(sanitized_content) {
        Ok(_) => info_msg("Sanitized content copied to clipboard successfully.", theme_map),
        Err(e) => warn_msg(&format!("Failed to copy to clipboard: {}", e), theme_map),
    }
}

fn handle_redaction_summary(
    summary: &[RedactionSummaryItem],
    opts: &CleanshOptions,
    theme_map: &ThemeMap,
) -> Result<()> {
    if !opts.no_redaction_summary && !opts.quiet {
        let stderr_supports_color = io::stderr().is_terminal();
        redaction_summary::print_summary(summary, &mut io::stderr(), theme_map, stderr_supports_color)?;
    }
    Ok(())
}

pub fn sanitize_single_line(
    line: &str,
    engine: &dyn SanitizationEngine,
) -> String {
    let (sanitized_content, _) = engine.sanitize(line, "", "", "", "", "", "", None)
        .unwrap_or_else(|_| (line.to_string(), Vec::new()));
    sanitized_content
}
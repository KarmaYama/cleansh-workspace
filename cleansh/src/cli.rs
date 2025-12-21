// cleansh/src/cli.rs
//! Command-line interface (CLI) definition for the renovated CleanSH v0.2.0.
//!
//! Focuses on initializing the TUI-native environment and the Self-Healing Engine.

use clap::Parser;
use std::path::PathBuf;

/// CleanSH v0.2.0: Proactive Terminal Security & Self-Healing.
///
/// This tool monitors your terminal streams in real-time, redacting sensitive
/// data and neutralizing leaked secrets via automated cloud provider revocation.
#[derive(Parser, Debug)]
#[command(
    name = "cleansh",
    author = "Relay Team",
    version = "0.2.0",
    about = "Securely redact and remediate sensitive data in real-time",
    arg_required_else_help = false,
)]
pub struct Cli {
    /// Load a specific security profile (defines rules and thresholds).
    #[arg(long, short = 'p', default_value = "default")]
    pub profile: String,

    /// Path to a custom redaction configuration file (YAML).
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Disable informational logging to keep the TUI display clean.
    #[arg(long, short = 'q', default_value_t = true)]
    pub quiet: bool,

    /// Enable verbose debug logging (redirects logs to 'cleansh.log').
    #[arg(long, short = 'd')]
    pub debug: bool,

    /// Set the max automated remediation actions per minute.
    #[arg(long, default_value_t = 5)]
    pub max_ops: usize,

    /// Use an organization-wide salt for consistent fingerprinting.
    #[arg(long, env = "CLEANSH_ORG_SALT")]
    pub org_salt: Option<String>,
}
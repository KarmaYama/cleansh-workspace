// cleansh/src/cli.rs
//! This file defines the command-line interface (CLI) for the cleansh application,
//! including all available commands and their arguments.
//! License: Polyform Noncommercial License 1.0.0

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Top-level CLI definition.
#[derive(Parser, Debug)]
#[command(
    name = "cleansh",
    author = "Obscura Team (Relay)",
    version = env!("CARGO_PKG_VERSION"),
    about = "Securely redact sensitive data from text",
    long_about = "Cleansh is a command-line utility for securely redacting sensitive information from text-based data. It helps you sanitize logs, code, documents, or terminal output to ensure that Personally Identifiable Information (PII) and other sensitive patterns are removed or obfuscated according to a configurable rule set.",
    arg_required_else_help = true,
)]
pub struct Cli {
    /// Disable informational messages
    #[arg(long, short = 'q', help = "Suppress all informational and debug messages.")]
    pub quiet: bool,

    /// Enable debug logging (overrides RUST_LOG for 'cleansh' crate to DEBUG)
    #[arg(long, short = 'd', help = "Enable debug logging.")]
    pub debug: bool,

    /// Explicitly disable debug logging, even if RUST_LOG is set to DEBUG
    #[arg(long = "disable-debug", help = "Disable debug logging, overriding RUST_LOG.")]
    pub disable_debug: bool,

    /// Specify the path to a custom YAML theme file.
    #[arg(long = "theme", value_name = "FILE", help = "Specify the path to a custom YAML theme file.")]
    pub theme: Option<PathBuf>,

    /// Disable donation prompts that appear after certain usage thresholds
    #[arg(long = "disable-donation-prompts", help = "Disable future prompts for donations.")]
    pub disable_donation_prompts: bool,

    /// Suppress donation prompt for this run only (does not persist).
    #[arg(long = "suppress-donation-prompt", help = "Suppress donation prompt for this run only (does not persist).", global = true)]
    pub suppress_donation_prompt: bool,

    /// The subcommand to run
    #[command(subcommand)]
    pub command: Commands,
}

/// All available commands for the `cleansh` CLI.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Sanitizes an input file or stdin, redacting sensitive information.
    #[command(about = "Sanitizes an input file or stdin, redacting sensitive information.")]
    Sanitize(SanitizeCommand),

    /// Scans an input for sensitive data and provides a detailed summary without redacting.
    #[command(about = "Scans an input for sensitive data and provides a detailed summary without redacting.")]
    Scan(ScanCommand),
    
    /// Uninstalls cleansh and removes its associated files.
    #[command(about = "Uninstall cleansh and remove its associated files.")]
    Uninstall {
        /// Proceed with uninstallation without confirmation.
        #[arg(long, short = 'y', help = "Proceed with uninstallation without a confirmation prompt.")]
        yes: bool,
    },
    
    /// Provides a suite of tools for managing redaction profiles.
    #[command(subcommand, about = "Provides a suite of tools for managing redaction profiles.")]
    Profiles(ProfilesCommand),
}

/// Arguments for the `sanitize` command.
#[derive(Parser, Debug)]
pub struct SanitizeCommand {
    /// Path to an input file (reads from stdin if not provided).
    #[arg(long, short = 'i', value_name = "FILE", help = "Read input from a specified file instead of stdin.")]
    pub input_file: Option<PathBuf>,

    /// Write sanitized output to this file instead of stdout.
    #[arg(long, short = 'o', value_name = "FILE", help = "Write output to a specified file instead of stdout.")]
    pub output: Option<PathBuf>,
    
    /// Copy sanitized output to the system clipboard.
    #[arg(long, short = 'c', help = "Copy sanitized output to the system clipboard.")]
    pub clipboard: bool,

    /// Show a unified diff to highlight the changes made.
    #[arg(long, short = 'D', help = "Show a unified diff to highlight the changes made.")]
    pub diff: bool,

    /// Path to a custom redaction configuration file (YAML).
    #[arg(long = "config", value_name = "FILE", help = "Path to a custom redaction configuration file (YAML).")]
    pub config: Option<PathBuf>,

    /// Loads a predefined profile from the local configuration.
    #[arg(long = "profile", value_name = "NAME", help = "Loads a predefined profile from the local configuration.")]
    pub profile: Option<String>,

    /// Explicitly enable only these rule names (comma-separated).
    #[arg(long, short = 'e', value_delimiter = ',', help = "Explicitly enable only these rule names (comma-separated).")]
    pub enable: Vec<String>,

    /// Explicitly disable these rule names (comma-separated).
    #[arg(long, short = 'x', value_delimiter = ',', help = "Explicitly disable these rule names (comma-separated).")]
    pub disable: Vec<String>,

    /// Select which sanitization engine to use.
    #[arg(long = "engine", value_name = "ENGINE", default_value = "regex", help = "Select a sanitization engine (e.g., 'regex' or 'entropy').")]
    pub engine: EngineChoice,

    /// Process input line by line (useful for streaming data from pipes).
    #[arg(long = "line-buffered", help = "Process input line by line (useful for streaming data from pipes).")]
    pub line_buffered: bool,

    /// Suppress the redaction summary.
    #[arg(long = "no-redaction-summary", help = "Suppress the redaction summary.")]
    pub no_summary: bool,

    /// Writes both the artifact JSON and the sanitized output into a single ZIP file.
    #[arg(long = "artifact-attach", value_name = "PATH", help = "Writes both the artifact JSON and the sanitized output into a single ZIP file.")]
    pub artifact_attach: Option<PathBuf>,

    /// Specifies the output path for the artifact JSON.
    #[arg(long = "artifact-out", value_name = "PATH", help = "Specifies the output path for the artifact JSON.")]
    pub artifact_out: Option<PathBuf>,

    /// Signs the canonical JSON blob using an RSA private key.
    #[arg(long = "artifact-key", value_name = "PATH", help = "Signs the canonical JSON blob using an RSA private key specified by this flag.")]
    pub artifact_key: Option<PathBuf>,
}

/// Arguments for the `scan` command.
#[derive(Parser, Debug)]
pub struct ScanCommand {
    /// Path to an input file (reads from stdin if not provided).
    #[arg(long, short = 'i', value_name = "FILE", help = "Read input from a specified file instead of stdin.")]
    pub input_file: Option<PathBuf>,

    /// Path to a custom redaction configuration file (YAML).
    #[arg(long = "config", value_name = "FILE", help = "Path to a custom redaction configuration file (YAML).")]
    pub config: Option<PathBuf>,

    /// Loads a predefined profile from the local configuration.
    #[arg(long = "profile", value_name = "NAME", help = "Loads a predefined profile from the local configuration.")]
    pub profile: Option<String>,
    
    /// Select the rule set (profile) to use for scanning. Defaults to the "default" ruleset.
    #[arg(long = "rules", value_name = "NAME", default_value = "default", help = "Select the rule set to use (defaults to 'default').")]
    pub rules: String,

    /// Explicitly enable only these rule names (comma-separated).
    #[arg(long = "enable", short = 'e', value_delimiter = ',', help = "Explicitly enable only these rule names (comma-separated).")]
    pub enable: Vec<String>,

    /// Explicitly disable these rule names (comma-separated).
    #[arg(long = "disable", short = 'x', value_delimiter = ',', help = "Explicitly disable these rule names (comma-separated).")]
    pub disable: Vec<String>,

    /// Exit with a non-zero code if the total number of detected secrets exceeds this threshold.
    #[arg(long = "fail-over-threshold", value_name = "N", help = "Exit with a non-zero code if the total number of detected secrets exceeds this threshold.")]
    pub fail_over_threshold: Option<usize>,

    /// Export scan summary to a JSON file.
    #[arg(long = "json-file", value_name = "FILE", help = "Export the redaction statistics to a JSON file.")]
    pub json_file: Option<PathBuf>,

    /// Print scan summary as JSON to stdout (conflicts with --json-file).
    #[arg(long = "json-stdout", conflicts_with = "json_file", help = "Export the redaction statistics to stdout as JSON.")]
    pub json_stdout: bool,

    /// Limit the number of unique sample matches displayed per rule in console output.
    #[arg(long = "sample-matches", value_name = "N", help = "Display a sample of up to N unique matches per rule in the console output.")]
    pub sample_matches: Option<usize>,
}

/// Arguments for the `verify-artifact` command.
#[derive(Parser, Debug)]
pub struct VerifyArtifactCommand {
    /// Checks the cryptographic signature of an artifact JSON file.
    #[arg(long = "verify-artifact", value_name = "FILE", help = "Checks the cryptographic signature of an artifact JSON file.")]
    pub verify_artifact: PathBuf,

    /// Provides the public key necessary to verify the signature.
    #[arg(long = "public-key", value_name = "PATH", help = "Provides the public key necessary to verify the signature.")]
    pub public_key: PathBuf,
}

/// Arguments for the `sync-profiles` command.
#[derive(Parser, Debug)]
pub struct SyncProfilesCommand {
    /// The unique identifier for the organization to sync profiles from.
    #[arg(long = "org-id", value_name = "ID", help = "The unique identifier for the organization to sync profiles from.")]
    pub org_id: String,

    /// Provides the API key for authenticating with the profile server.
    #[arg(long = "org-key", value_name = "KEY", help = "Provides the API key for authenticating with the profile server.")]
    pub org_key: String,
}

/// Subcommands for the `profiles` command.
#[derive(Subcommand, Debug)]
pub enum ProfilesCommand {
    #[command(about = "Signs a profile YAML file using a key from a file.")]
    Sign {
        /// The path to the profile YAML file to sign.
        #[arg(value_name = "FILE", help = "The path to the profile YAML file to sign.")]
        path: PathBuf,
        /// The path to the key file for signing.
        #[arg(long = "key", value_name = "KEY_FILE", help = "The path to the key file for signing.")]
        key_file: PathBuf,
    },
    #[command(about = "Verifies the signature of a profile YAML file.")]
    Verify {
        /// The path to the profile YAML file to verify.
        #[arg(value_name = "FILE", help = "The path to the profile YAML file to verify.")]
        path: PathBuf,
        /// The path to the public key for verification.
        #[arg(long = "public-key", value_name = "PUB_KEY_FILE", help = "The path to the public key for verification.")]
        pub_key_file: PathBuf,
    },
    #[command(about = "Lists all available local profiles.")]
    List,
}

/// Enum for selecting the sanitization engine.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum EngineChoice {
    /// The default regular expression engine.
    Regex,
    /// The dynamic contextual entropy engine (Pro feature).
    Entropy,
}
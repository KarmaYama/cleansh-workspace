// cleansh/src/lib.rs
//! Cleansh CLI Application
//!
//! `cleansh` is the command-line interface application that allows users to
//! sanitize sensitive information from text content.
//!
//! ## License
//!
//! Licensed under the MIT or Apache-2.0 license.

#![doc = include_str!("../README.md")]

pub mod commands;
pub mod cli;
pub mod ui;
pub mod utils;
pub mod logger;

// NOTE: License checking logic has been removed as part of the Open Core transition.
// The CLI is now free for all users for local operations.

// Test-only exports
#[cfg(any(test, feature = "test-exposed"))]
pub mod test_exposed {
    /// Core config types & constants
    pub mod config {
        pub use cleansh_core::config::{
            MAX_PATTERN_LENGTH,
            RedactionConfig,
            RedactionRule,
            RedactionSummaryItem,
            RuleConfigNotFoundError,
            merge_rules,
        };
    }

    /// Core sanitizer functions
    pub mod sanitizer {
        pub use cleansh_core::{
            CompiledRule,
            CompiledRules,
            compile_rules,
        };
    }

    /// Core redaction-match types
    pub mod redaction_match {
        pub use cleansh_core::redaction_match::{
            RedactionMatch,
            redact_sensitive,
        };
    }

    /// Core validators
    pub mod validators {
        pub use cleansh_core::validators::{
            is_valid_ssn_programmatically,
            is_valid_uk_nino_programmatically,
        };
    }

    /// CLI commands for testing
    pub mod commands {
        pub use crate::commands::cleansh::{run_cleansh_opts, sanitize_single_line};
        pub use crate::commands::stats::run_stats_command;
        pub use crate::commands::uninstall::elevate_and_run_uninstall;
    }

    /// CLI UI modules for testing
    pub mod ui {
        pub use crate::ui::diff_viewer;
        pub use crate::ui::output_format;
        pub use crate::ui::redaction_summary;
        pub use crate::ui::theme;
        pub use crate::ui::verify_ui;
        pub use crate::ui::sync_ui;
    }

    /// CLI utility modules for testing
    pub mod utils {
        pub use crate::utils::app_state::*;
        pub use crate::utils::platform::*;
        pub use crate::utils::clipboard::*;
    }

    /// CLI logger for testing
    pub mod logger {
        pub use crate::logger::*;
    }
}
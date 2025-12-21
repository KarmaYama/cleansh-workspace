// cleansh/src/lib.rs
//! # CleanSH CLI/TUI Application
//!
//! This crate provides the terminal interface for the CleanSH security engine.
//! Starting in v0.2.0, this is a fully asynchronous TUI-native application.

pub mod commands;
pub mod cli;
pub mod ui;
pub mod utils;
pub mod logger;
pub mod tui;

// Re-export core TUI runner
pub use tui::run_tui;

#[cfg(any(test, feature = "test-exposed"))]
pub mod test_exposed {
    pub mod config {
        pub use cleansh_core::config::*;
    }
    pub mod redaction_match {
        pub use cleansh_core::redaction_match::*;
    }
    pub mod utils {
        pub use crate::utils::app_state::*;
        pub use crate::utils::platform::*;
    }
}
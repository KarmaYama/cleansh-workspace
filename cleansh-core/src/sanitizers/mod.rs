//! Core regex sanitization engine for CleanSH.
//!
//! This module is responsible for compiling redaction rules into efficient regular expressions
//! and applying them to input content. It handles the actual process of identifying sensitive
//! data, performing programmatic validation where necessary, and replacing the matched content
//! with a specified replacement string. It also manages the stripping of ANSI escape codes
//! to ensure accurate pattern matching on raw text.
//!
//! This module works closely with `config` (for rule definitions), `validators` (for
//! advanced pattern validation), and `redaction_match` (for logging and result types).

pub mod compiler;
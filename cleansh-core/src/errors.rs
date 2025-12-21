//! errors.rs - Custom error types for the cleansh-core library.
//!
//! This module defines a structured error enum for the library, providing
//! specific, actionable error types that can be handled programmatically.
//!
//! License: MIT OR APACHE 2.0

use thiserror::Error;

/// This enum represents all possible error types in the `cleansh-core` library.
///
/// By using `#[non_exhaustive]`, we signal to consumers of this library that
/// new variants may be added in future versions. This prevents them from
/// matching all variants exhaustively, thus avoiding breaking changes.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CleanshError {
    #[error("Failed to compile redaction rule '{0}': {1}")]
    RuleCompilationError(String, regex::Error),

    #[error("Rule '{0}': pattern length ({1}) exceeds maximum allowed ({2})")]
    PatternLengthExceeded(String, usize, usize),

    #[error("Failed to serialize configuration for hashing: {0}")]
    SerializationError(String),

    #[error("An unexpected I/O error occurred: {0}")]
    IoError(#[from] std::io::Error),

    #[error("A critical system error occurred: {0}")]
    AnyhowWrapper(#[from] anyhow::Error),
    
    // Add other specific error types as the project grows
    #[error("A fatal error occurred: {0}")]
    Fatal(String),
}
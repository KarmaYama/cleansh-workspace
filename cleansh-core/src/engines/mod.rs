// cleansh-core/src/engines/mod.rs
//! This module contains different sanitization engine implementations.
//!
//! Each engine is a separate file within this directory and implements the
//! `SanitizationEngine` trait. This modular design allows for easy addition
//! of new engine types, such as entropy-based or ML-based sanitizers.
//!
//! To add a new engine, create a new file (e.g., `entropy_engine.rs`),
//! define its logic, and declare it here using `pub mod <engine_name>;`.
//!
//! # License
//! BUSL-1.1

pub mod regex_engine;
pub mod entropy_engine;
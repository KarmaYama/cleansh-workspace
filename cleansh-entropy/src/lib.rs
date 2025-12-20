// cleansh-entropy/src/lib.rs
#![no_std]

extern crate alloc; 

#[cfg(feature = "std")]
extern crate std;

pub mod entropy;
pub mod scanner;
pub mod statistics;
pub mod context;
pub mod scoring;
pub mod engine;

/// Common type definitions
pub type EntropyScore = f64;
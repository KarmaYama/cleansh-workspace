//! compiler.rs - Manages the compilation and caching of redaction rules.
//!
//! This module provides a thread-safe, cached mechanism to convert a
//! `RedactionConfig` into `CompiledRules`, which are optimized for
//! efficient sanitization. It uses a global, shared cache to avoid
//! redundant compilation.
//!
//! License: MIT OR APACHE 2.0

use anyhow::Result;
use log::{debug, warn};
use regex::{Regex, RegexBuilder};
use lazy_static::lazy_static;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use crate::config::{RedactionRule, RedactionConfig, MAX_PATTERN_LENGTH};
use crate::errors::CleanshError;

/// Represents a single compiled redaction rule.
///
/// This struct holds a compiled regular expression along with its associated
/// replacement text and metadata, ready for efficient application to content.
#[derive(Debug)]
pub struct CompiledRule {
    /// The compiled regular expression used for matching.
    pub regex: Regex,
    /// The string to replace matches of this rule's pattern with.
    pub replace_with: String,
    /// The unique name of the redaction rule.
    pub name: String,
    /// A flag indicating if this rule requires additional programmatic validation.
    pub programmatic_validation: bool,
}

/// Represents a collection of all compiled rules for efficient sanitization.
///
/// This struct acts as the primary container for the set of rules that will be
/// applied during a sanitization operation.
#[derive(Debug)]
pub struct CompiledRules {
    /// A vector of `CompiledRule` instances ready for application.
    pub rules: Vec<CompiledRule>,
}

lazy_static! {
    /// A thread-safe, global cache for compiled rules.
    /// The key is a hash of the serialized `RedactionConfig`.
    static ref COMPILED_RULES_CACHE: RwLock<HashMap<u64, Arc<CompiledRules>>> = RwLock::new(HashMap::new());
}

/// Hashes the `RedactionConfig` to create a stable, unique key for the cache.
///
/// To ensure determinism, the rules are sorted by name before hashing.
fn hash_config(config: &RedactionConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    let mut rules_to_hash = config.rules.clone();
    
    // Sort rules to ensure a deterministic hash key.
    rules_to_hash.sort_by(|a, b| a.name.cmp(&b.name));

    // Hash the sorted rules.
    rules_to_hash.hash(&mut hasher);
    hasher.finish()
}

/// Compiles a list of `RedactionRule`s into `CompiledRules` for efficient matching.
/// This is the low-level function that performs the actual regex compilation.
pub fn compile_rules(rules_to_compile: Vec<RedactionRule>) -> Result<CompiledRules, CleanshError> {
    debug!("Starting compilation of {} rules.", rules_to_compile.len());

    let mut compiled_rules = Vec::new();
    let mut compilation_errors = Vec::new();

    for rule in rules_to_compile {
        match rule.pattern.as_ref() {
            Some(pattern) => {
                debug!(
                    "Attempting to compile rule: '{}' with pattern '{:?}'",
                    &rule.name, pattern
                );
                
                if pattern.len() > MAX_PATTERN_LENGTH {
                    compilation_errors.push(CleanshError::PatternLengthExceeded(
                        rule.name, 
                        pattern.len(), 
                        MAX_PATTERN_LENGTH
                    ));
                    continue;
                }

                let regex_result = RegexBuilder::new(pattern)
                    .multi_line(rule.multiline)
                    .dot_matches_new_line(rule.dot_matches_new_line)
                    .size_limit(10 * (1 << 20)) // 10 MB limit for compiled regex
                    .build();

                match regex_result {
                    Ok(regex) => {
                        log::debug!(
                            target: "cleansh_core::sanitizer",
                            "Rule '{}' compiled successfully.",
                            &rule.name
                        );
                        compiled_rules.push(CompiledRule {
                            regex,
                            replace_with: rule.replace_with,
                            name: rule.name,
                            programmatic_validation: rule.programmatic_validation,
                        });
                    }
                    Err(e) => {
                        compilation_errors.push(CleanshError::RuleCompilationError(rule.name, e));
                    }
                }
            }
            None => {
                warn!("Skipping rule '{}' because its pattern is missing.", &rule.name);
                continue;
            }
        }
    }

    if !compilation_errors.is_empty() {
        // Collect errors into a single string for a concise error report
        let error_message = compilation_errors.iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>()
            .join("\n");
        Err(CleanshError::Fatal(format!("Failed to compile {} rule(s):\n{}", compilation_errors.len(), error_message)))
    } else {
        debug!(
            "Finished compiling rules. Total compiled: {}.",
            compiled_rules.len()
        );
        Ok(CompiledRules { rules: compiled_rules })
    }
}

/// Gets a `CompiledRules` instance from the cache or compiles them if not found.
///
/// This is the public entry point for retrieving compiled rules. It returns an `Arc`
/// to a `CompiledRules` instance, allowing for cheap sharing.
pub fn get_or_compile_rules(config: &RedactionConfig) -> Result<Arc<CompiledRules>> {
    let cache_key = hash_config(config);
    
    // Attempt to acquire a read lock first.
    {
        let cache = COMPILED_RULES_CACHE.read().unwrap();
        if let Some(rules) = cache.get(&cache_key) {
            debug!("Serving compiled rules from cache for key: {}", &cache_key);
            return Ok(Arc::clone(rules));
        }
    } // Read lock is released here.

    // Not in cache, so we compile.
    debug!("Compiled rules not found in cache. Compiling now.");
    let compiled = compile_rules(config.rules.clone())?;
    let compiled_arc = Arc::new(compiled);

    // Acquire a write lock to insert the new rules.
    COMPILED_RULES_CACHE.write().unwrap().insert(cache_key, Arc::clone(&compiled_arc));
    
    debug!("Successfully compiled and cached rules for key: {}", &cache_key);
    Ok(compiled_arc)
}
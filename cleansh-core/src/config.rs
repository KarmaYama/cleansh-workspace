//! Configuration management for `CleanSH-core`.
//!
//! This module defines the core data structures for redaction rules and engine configurations.
//! It handles serialization/deserialization of YAML configurations and provides utilities
//! for loading, merging, and validating these configs.
//!
//! License: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use log::{debug, info, warn};
use std::fmt;
use regex::Regex;
use std::hash::{Hash, Hasher};

/// Maximum allowed length for a regex pattern string.
pub const MAX_PATTERN_LENGTH: usize = 500;

/// Represents a single redaction rule used by the Regex engine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct RedactionRule {
    /// Unique identifier for the rule (e.g., "aws_access_key").
    pub name: String,
    /// Human-readable description of what the rule targets.
    pub description: Option<String>,
    /// The regex pattern string.
    pub pattern: Option<String>,
    /// The type of pattern (e.g., "regex", "entropy").
    pub pattern_type: String,
    /// The string to replace matches with.
    pub replace_with: String,
    pub version: String,
    pub created_at: String,
    pub author: String,
    pub updated_at: String,
    /// If true, enables multiline mode for the regex engine.
    pub multiline: bool,
    /// If true, the dot character `.` in regex will match newlines.
    pub dot_matches_new_line: bool,
    /// If true, the rule is disabled unless explicitly enabled in the profile.
    pub opt_in: bool,
    /// If true, requires external programmatic validation (e.g., SSN checksum).
    pub programmatic_validation: bool,
    /// Explicit override for enabling/disabling the rule.
    pub enabled: Option<bool>,
    /// Security severity level (e.g., "high", "medium").
    pub severity: Option<String>,
    /// Metadata tags for categorization.
    pub tags: Option<Vec<String>>,
}

impl Hash for RedactionRule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.description.hash(state);
        self.pattern.hash(state);
        self.pattern_type.hash(state);
        self.replace_with.hash(state);
        self.version.hash(state);
        self.created_at.hash(state);
        self.author.hash(state);
        self.updated_at.hash(state);
        self.multiline.hash(state);
        self.dot_matches_new_line.hash(state);
        self.opt_in.hash(state);
        self.programmatic_validation.hash(state);
        self.enabled.hash(state);
        self.severity.hash(state);
    }
}

impl Default for RedactionRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: None,
            pattern: None,
            pattern_type: "regex".to_string(),
            replace_with: "[REDACTED]".to_string(),
            version: "1.0.0".to_string(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            updated_at: "1970-01-01T00:00:00Z".to_string(),
            author: "Relay Team".to_string(),
            multiline: false,
            dot_matches_new_line: false,
            opt_in: false,
            programmatic_validation: false,
            enabled: None,
            severity: None,
            tags: None,
        }
    }
}

/// Configuration settings specific to the Entropy Engine.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct EntropyConfig {
    /// The confidence threshold for flagging a token as a secret (default: 0.5).
    pub threshold: Option<f64>,
    /// The size of the scanning window in bytes (default: 24).
    /// Smaller windows are more aggressive; larger windows reduce noise.
    pub window_size: Option<usize>,
}

impl Hash for EntropyConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(t) = self.threshold {
            t.to_bits().hash(state);
        } else {
            0u64.hash(state);
        }
        self.window_size.hash(state);
    }
}

/// Container for all engine-specific configurations.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Hash)]
#[serde(default)]
pub struct EngineConfig {
    pub entropy: EntropyConfig,
}

/// Represents the top-level configuration structure for CleanSH.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct RedactionConfig {
    /// A list of regex-based redaction rules.
    pub rules: Vec<RedactionRule>,
    /// Engine-specific settings (e.g., entropy thresholds and windows).
    #[serde(default)]
    pub engines: EngineConfig,
}

/// Represents a single item in the redaction summary for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSummaryItem {
    pub rule_name: String,
    pub occurrences: usize,
    pub original_texts: Vec<String>,
    pub sanitized_texts: Vec<String>,
}

/// Error type for missing rule configurations.
#[derive(Debug)]
pub struct RuleConfigNotFoundError {
    pub config_name: String,
}

impl fmt::Display for RuleConfigNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rule configuration '{}' not found.", self.config_name)
    }
}

impl std::error::Error for RuleConfigNotFoundError {}

impl RedactionConfig {
    /// Loads redaction rules from a YAML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        info!("Loading custom rules from: {}", path.display());
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file {}", path.display()))?;
        let config: RedactionConfig = serde_yml::from_str(&text)
            .with_context(|| format!("Failed to parse config file {}", path.display()))?;

        validate_rules(&config.rules)?;
        info!("Loaded {} rules from file {}.", config.rules.len(), path.display());
        
        Ok(config)
    }

    /// Loads default redaction rules from the embedded configuration.
    pub fn load_default_rules() -> Result<Self> {
        debug!("Loading default rules from embedded string...");
        let default_yaml = include_str!("../config/default_rules.yaml");
        let config: RedactionConfig = serde_yml::from_str(default_yaml)
            .context("Failed to parse default rules")?;

        debug!("Loaded {} default rules.", config.rules.len());
        Ok(config)
    }

    /// Filters active rules based on enable/disable lists provided via CLI.
    pub fn set_active_rules(&mut self, enable_rules: &[String], disable_rules: &[String]) {
        let enable_set: HashSet<&str> = enable_rules.iter().map(String::as_str).collect();
        let disable_set: HashSet<&str> = disable_rules.iter().map(String::as_str).collect();

        debug!("Initial rules count before filtering: {}", self.rules.len());
        
        let all_rule_names: HashSet<&str> = self.rules.iter().map(|r| r.name.as_str()).collect();

        for rule_name in enable_set.difference(&all_rule_names) {
            warn!("Rule '{}' in `enable_rules` list does not exist.", rule_name);
        }

        for rule_name in disable_set.difference(&all_rule_names) {
            warn!("Rule '{}' in `disable_rules` list does not exist.", rule_name);
        }

        self.rules.retain(|rule| {
            let rule_name_str = rule.name.as_str();
            !disable_set.contains(rule_name_str) && (!rule.opt_in || enable_set.contains(rule_name_str))
        });

        debug!("Final active rules count after filtering: {}", self.rules.len());
    }
}

/// Merges user-defined rules and engine settings with defaults.
pub fn merge_rules(
    default_config: RedactionConfig,
    user_config: Option<RedactionConfig>,
) -> RedactionConfig {
    debug!("merge_rules called. Initial default rules count: {}", default_config.rules.len());
    
    let mut final_rules_map: HashMap<String, RedactionRule> = default_config.rules.into_iter()
        .map(|rule| (rule.name.clone(), rule))
        .collect();

    let mut final_engines = default_config.engines;

    if let Some(user_cfg) = user_config {
        debug!("User config provided. Merging {} user rules.", user_cfg.rules.len());
        for user_rule in user_cfg.rules {
            final_rules_map.insert(user_rule.name.clone(), user_rule);
        }
        
        if let Some(user_threshold) = user_cfg.engines.entropy.threshold {
             debug!("Overriding entropy threshold with user value: {}", user_threshold);
             final_engines.entropy.threshold = Some(user_threshold);
        }

        if let Some(user_window) = user_cfg.engines.entropy.window_size {
            debug!("Overriding entropy window size with user value: {}", user_window);
            final_engines.entropy.window_size = Some(user_window);
        }
    }

    let final_rules: Vec<RedactionRule> = final_rules_map.into_values().collect();
    debug!("Final total rules after merge: {}", final_rules.len());

    RedactionConfig { 
        rules: final_rules,
        engines: final_engines,
    }
}

/// Validates rule integrity (regex compilation, capture groups).
fn validate_rules(rules: &[RedactionRule]) -> Result<()> {
    let mut rule_names = HashSet::new();
    let mut errors = Vec::new();
    let capture_group_regex = Regex::new(r"\$(\d+)").unwrap();

    for rule in rules {
        if rule.name.is_empty() {
            errors.push("A rule has an empty `name` field.".to_string());
        } else if !rule_names.insert(rule.name.clone()) {
            errors.push(format!("Duplicate rule name found: '{}'.", rule.name));
        }

        if rule.pattern_type == "regex" {
            let pattern = match &rule.pattern {
                Some(p) => p,
                None => {
                    errors.push(format!("Rule '{}' is missing the `pattern` field.", rule.name));
                    continue;
                }
            };

            if pattern.is_empty() {
                errors.push(format!("Rule '{}' has an empty `pattern` field.", rule.name));
            }
            
            if let Err(e) = Regex::new(pattern) {
                errors.push(format!("Rule '{}' has an invalid regex pattern: {}", rule.name, e));
                continue;
            }
            
            let mut group_count = 0;
            let mut is_escaped = false;
            for c in pattern.chars() {
                match c {
                    '\\' => is_escaped = !is_escaped,
                    '(' if !is_escaped => group_count += 1,
                    _ => is_escaped = false,
                }
            }

            for cap in capture_group_regex.captures_iter(&rule.replace_with) {
                if let Some(group_num_str) = cap.get(1) {
                    if let Ok(group_num) = group_num_str.as_str().parse::<usize>() {
                        if group_num > group_count {
                            errors.push(format!(
                                "Rule '{}': replacement references non-existent capture group '${}'.",
                                rule.name, group_num
                            ));
                        }
                    }
                }
            }
        }
    }

    if !errors.is_empty() {
        let full_error_message = format!("Rule validation failed:\n{}", errors.join("\n"));
        Err(anyhow!(full_error_message))
    } else {
        Ok(())
    }
}
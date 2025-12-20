// File: cleansh-core/src/profiles.rs

//! profiles.rs - Profile configuration, loading, and helpers for CleanSH.
//!
//! This module provides the data structures and logic for defining and managing redaction
//! profiles. A profile specifies which rules are enabled, their severity, and advanced
//! engine settings like sampling and token formatting. This allows users to create
//! named, reusable configurations tailored for specific compliance needs (e.g., GDPR, CCPA).
//!
//! The module handles loading a profile from a YAML file, merging its settings with the
//! default rule set, and providing deterministic functions for sampling and token
//! generation to support secure, auditable reporting.
//!
//!
//! license: MIT OR Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::{HashSet, HashMap};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;
use tinytemplate::TinyTemplate;
use log::{debug, warn};
use chrono::NaiveDate;
use serde_yml::Value; 

use crate::config::{RedactionConfig, RedactionRule};
use crate::redaction_match::RedactionMatch;

type HmacSha256 = Hmac<Sha256>;

// A fixed salt used to generate deterministic run seeds.
// This replaces the usage of dynamic strings as cryptographic keys, resolving CodeQL security alerts.
const SEED_GENERATION_SALT: &[u8] = b"cleansh-run-seed-generation-v1-salt";

/// The top-level structure representing a redaction profile configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case", default)]
pub struct ProfileConfig {
    pub profile_name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub version: String,
    pub profile_id: Option<String>,
    pub author: Option<String>,
    pub compliance_scope: Option<String>,
    pub revision_date: Option<NaiveDate>,
    pub signature: Option<String>,
    pub signature_alg: Option<String>,
    pub rules: Vec<ProfileRule>,
    pub samples: Option<SamplesConfig>,
    pub dedupe: Option<DedupeConfig>,
    pub post_processing: Option<PostProcessingConfig>,
    pub reporting: Option<ReportingConfig>,
}

impl ProfileConfig {
    pub fn validate(&self, default_config: &RedactionConfig) -> Result<()> {
        if self.version.trim().is_empty() {
            bail!("Profile '{}' validation failed: 'version' field cannot be empty.", self.profile_name);
        }

        let default_rule_names: HashSet<&str> = default_config.rules.iter().map(|r| r.name.as_str()).collect();
        for rule_override in &self.rules {
            if !default_rule_names.contains(rule_override.name.as_str()) {
                bail!("Profile '{}' validation failed: rule '{}' not found in default configuration.",
                    self.profile_name, rule_override.name);
            }
        }

        if let Some(samples) = &self.samples {
            if samples.max_per_rule == 0 {
                bail!("Profile '{}' validation failed: 'samples.max_per_rule' must be greater than 0.", self.profile_name);
            }
            if samples.max_total > 0 && samples.max_per_rule > samples.max_total {
                bail!("Profile '{}' validation failed: 'samples.max_per_rule' cannot exceed 'samples.max_total'.", self.profile_name);
            }
        }

        if let Some(dedupe) = &self.dedupe {
            if dedupe.window_bytes == 0 && dedupe.use_hash {
                warn!("Profile '{}': 'dedupe.window_bytes' is 0, but 'use_hash' is true. Deduplication will not use a window.", self.profile_name);
            }
        }

        Ok(())
    }

    /// Verifies the HMAC-SHA256 signature of the profile against the provided secret key.
    ///
    /// This method is crucial for ensuring the integrity and authenticity of a profile
    /// loaded from disk. It recalculates the signature from the profile's content
    /// (excluding the signature field itself) and compares it with the stored signature.
    /// The `raw_bytes` argument is the full content of the YAML file.
    ///
    /// # Arguments
    /// * `raw_bytes` - The complete raw bytes of the YAML file, used to recompute the signature.
    /// * `key` - The secret key used to generate the HMAC signature.
    pub fn verify_signature(&self, raw_bytes: &[u8], key: &[u8]) -> Result<bool> {
        if self.signature.is_none() {
            debug!("Profile '{}' is unsigned, skipping signature verification.", self.profile_name);
            return Ok(true);
        }

        let stored_signature = self.signature.as_ref().unwrap();
        
        if self.signature_alg.as_deref() != Some("hmac-sha256") {
            bail!("Profile '{}' signature verification failed: Unsupported signature algorithm '{}'. Only 'hmac-sha256' is supported.",
                self.profile_name, self.signature_alg.as_deref().unwrap_or("none"));
        }

        debug!("Profile '{}': Verifying signature...", self.profile_name);
        
        let raw_for_signing = get_raw_profile_for_signature(raw_bytes)?;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| anyhow!("Failed to initialize HMAC-SHA256 with key: {}", e))?;
        mac.update(&raw_for_signing);

        let computed_signature = hex::encode(mac.finalize().into_bytes());

        if computed_signature.eq_ignore_ascii_case(stored_signature) {
            debug!("Profile '{}' signature verification succeeded.", self.profile_name);
            Ok(true)
        } else {
            warn!("Profile '{}' signature verification failed. Stored: '{}', Computed: '{}'",
                self.profile_name, stored_signature, computed_signature);
            Err(anyhow!("Profile signature verification failed for profile '{}'. The profile may have been tampered with.", self.profile_name))
        }
    }
}

/// A helper function to parse the raw YAML bytes and re-serialize the profile
/// with the `signature` field removed.
fn get_raw_profile_for_signature(raw_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut profile_value: Value = serde_yml::from_slice(raw_bytes)
        .context("Failed to parse profile YAML for signature verification.")?;

    if let Value::Mapping(mapping) = &mut profile_value {
        if mapping.contains_key(&Value::String("signature".to_string())) {
            mapping.remove(&Value::String("signature".to_string()));
        }
        if mapping.contains_key(&Value::String("signature_alg".to_string())) {
            mapping.remove(&Value::String("signature_alg".to_string()));
        }
    }

    serde_yml::to_string(&profile_value)
        .context("Failed to re-serialize profile for signature verification.")
        .map(|s| s.as_bytes().to_vec())
}


#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct ProfileRule {
    pub name: String,
    pub enabled: Option<bool>,
    pub severity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct SamplesConfig {
    pub max_per_rule: usize,
    pub max_total: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct DedupeConfig {
    pub window_bytes: usize,
    pub use_hash: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct PostProcessingConfig {
    pub replace_with_token: bool,
    pub token_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct ReportingConfig {
    pub include_rule_version: bool,
    pub include_engine_version: bool,
    pub include_byte_hash_of_input: bool,
}

pub fn profile_candidate_paths(name: &str) -> Vec<PathBuf> {
    let base_dirs = vec![
        dirs::home_dir().map(|p| p.join(".cleansh").join("profiles")),
        dirs::config_dir().map(|p| p.join("cleansh").join("profiles")),
        Some(PathBuf::from("/etc/cleansh/profiles")),
        Some(PathBuf::from("./config")),
        Some(PathBuf::from("../config")),
    ];

    base_dirs.into_iter()
        .flatten()
        .map(|dir| dir.join(format!("{}.yaml", name)))
        .collect()
    
}

pub fn load_profile_by_name(name_or_path: &str) -> Result<ProfileConfig> {
    debug!("Attempting to load profile from: '{}'", name_or_path);
    
    let path_to_load = {
        let path = Path::new(name_or_path);
        if path.exists() && path.is_file() {
            debug!("Input is a valid file path. Loading directly from: {}", path.display());
            Some(path.to_path_buf())
        } else {
            profile_candidate_paths(name_or_path)
                .into_iter()
                .find(|p| p.exists())
        }
    }.context("Profile not found. It is not a valid file path, and was not found in expected locations.")?;
    
    let raw_bytes = fs::read(&path_to_load)
        .with_context(|| format!("reading profile file {}", path_to_load.display()))?;
    
    let cfg: ProfileConfig = serde_yml::from_slice(&raw_bytes)
        .with_context(|| format!("parsing profile YAML {}", path_to_load.display()))?;
    
    if let Some(key_hex) = std::env::var("CLEANSH_PROFILE_KEY").ok() {
        let key_bytes = hex::decode(&key_hex)
            .context("Failed to decode CLEANSH_PROFILE_KEY from hex. Make sure it's a valid hex string.")?;
        cfg.verify_signature(&raw_bytes, &key_bytes)?;
    } else if cfg.signature.is_some() {
        warn!("Profile '{}' is signed, but CLEANSH_PROFILE_KEY environment variable is not set. Signature verification skipped.", cfg.profile_name);
    }
    
    debug!("Successfully loaded profile '{}'.", name_or_path);
    Ok(cfg)
}

/// Signs a profile file using an HMAC-SHA256 key and updates the file in place.
/// This function is intended to be used by a separate command-line utility.
///
/// # Arguments
/// * `path` - The path to the profile YAML file to sign.
/// * `key` - The secret key used to generate the HMAC signature.
pub fn sign_profile(path: &Path, key: &[u8]) -> Result<()> {
    debug!("Signing profile file: {}", path.display());
    
    let raw_bytes = fs::read(path)
        .with_context(|| format!("reading profile file {}", path.display()))?;
    
    let raw_for_signing = get_raw_profile_for_signature(&raw_bytes)?;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to initialize HMAC-SHA256 for signing: {}", e))?;
    mac.update(&raw_for_signing);
    let signature = hex::encode(mac.finalize().into_bytes());

    let mut cfg: ProfileConfig = serde_yml::from_slice(&raw_bytes)
        .with_context(|| format!("parsing profile YAML for signing {}", path.display()))?;
    cfg.signature = Some(signature);
    cfg.signature_alg = Some("hmac-sha256".to_string());
    
    let updated_yaml = serde_yml::to_string(&cfg)
        .context("Failed to re-serialize signed profile.")?;
    fs::write(path, updated_yaml)
        .with_context(|| format!("writing signed profile to file {}", path.display()))?;

    debug!("Successfully signed profile '{}'.", cfg.profile_name);
    Ok(())
}

pub fn apply_profile_to_config(profile: &ProfileConfig, mut default: RedactionConfig) -> RedactionConfig {
    debug!("Applying profile '{}' to default rules.", profile.profile_name);

    let mut default_rules_map: HashMap<String, &mut RedactionRule> = default.rules.iter_mut()
        .map(|r| (r.name.clone(), r))
        .collect();

    for profile_rule_override in &profile.rules {
        if let Some(rule_to_update) = default_rules_map.get_mut(&profile_rule_override.name) {
            if let Some(enabled) = profile_rule_override.enabled {
                debug!("Applying enabled={} override for rule '{}'", enabled, &profile_rule_override.name);
                rule_to_update.enabled = Some(enabled);
            }
            if let Some(severity) = profile_rule_override.severity.clone() {
                debug!("Applying severity='{}' override for rule '{}'", severity, &profile_rule_override.name);
                rule_to_update.severity = Some(severity);
            }
        } else {
            warn!("Profile rule '{}' not found in default configuration. It will be ignored.", profile_rule_override.name);
        }
    }
    
    debug!("Finished applying profile. Final rule count: {}", default.rules.len());
    default
}

/// Normalizes an input string for consistent hashing.
/// It trims whitespace, converts to lowercase, and can provide a default value for empty strings.
/// 
/// # Arguments
/// * `s` - The string slice to normalize.
/// * `default_value` - An optional string slice to use if `s` is empty or only contains whitespace.
fn normalize_input(s: &str, default_value: Option<&str>) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        default_value.unwrap_or("").to_string()
    } else {
        trimmed.to_lowercase()
    }
}

pub fn compute_run_seed(profile_version: &str, run_id: &str, engine_version: &str) -> Result<Vec<u8>> {
    let normalized_version = normalize_input(profile_version, None);
    let normalized_run_id = normalize_input(run_id, None);
    // This value is no longer used as a key, but as data.
    let normalized_engine_version = normalize_input(engine_version, Some("default"));
    
    // FIX: Use the constant SALT as the key.
    // This satisfies CodeQL because we aren't using a string literal from a helper function as a key.
    let mut mac = HmacSha256::new_from_slice(SEED_GENERATION_SALT)
        .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;

    // Mix all inputs into the data stream
    mac.update(normalized_version.as_bytes());
    mac.update(normalized_run_id.as_bytes());
    mac.update(normalized_engine_version.as_bytes()); // Now treated as data
    
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn sample_score_hex(run_seed: &[u8], source_id: &str, start: u64, end: u64) -> Result<String> {
    Ok(hex::encode(sample_score_bytes(run_seed, source_id, start, end)?))
}

pub fn sample_score_bytes(run_seed: &[u8], source_id: &str, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(run_seed)
        .map_err(|e| anyhow!("Failed to create HMAC from run seed: {}", e))?;
    mac.update(source_id.as_bytes());
    mac.update(start.to_string().as_bytes());
    mac.update(end.to_string().as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn select_samples_for_rule(matches: &[RedactionMatch], run_seed: &[u8], max_per_rule: usize) -> Vec<RedactionMatch> {
    let mut scored: Vec<(Vec<u8>, &RedactionMatch)> = matches.iter()
        .filter_map(|m| {
            sample_score_bytes(run_seed, &m.source_id, m.start, m.end)
                .ok()
                .map(|s| (s, m))
        })
        .collect();
    
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    
    let mut out: Vec<RedactionMatch> = Vec::new();
    let mut seen_hashes = HashSet::new();
    let mut seen_coords = HashSet::new();
    
    for (_score, m) in scored.into_iter() {
        if out.len() >= max_per_rule { break; }
        
        let is_duplicate = if let Some(h) = &m.sample_hash {
            !seen_hashes.insert(h.clone())
        } else {
            !seen_coords.insert((m.source_id.clone(), m.start, m.end))
        };
        
        if !is_duplicate {
            out.push(m.clone());
        }
    }
    out
}

pub fn format_token(token_fmt: &str, rule: &str, sample_hash_hex: &str) -> Result<String> {
    let mut tt = TinyTemplate::new();
    tt.add_template("t", token_fmt)
        .context("Failed to parse token template")?;
    let shorthash = if sample_hash_hex.len() >= 8 { &sample_hash_hex[0..8] } else { sample_hash_hex };
    let ctx = serde_json::json!({ "rule": rule, "shorthash": shorthash });
    tt.render("t", &ctx).map_err(|e| anyhow!("Failed to render token template: {}", e))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub profile_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineOptions {
    pub post_processing: Option<PostProcessingConfig>,
    pub samples_config: Option<SamplesConfig>,
    pub dedupe_config: Option<DedupeConfig>,
    pub run_seed: Option<Vec<u8>>,
    pub engine_version: Option<String>,
    
    pub profile_meta: ProfileMeta,
    
    pub run_id: Option<String>,
    pub input_hash: Option<String>,
}

impl From<ProfileConfig> for EngineOptions {
    fn from(profile: ProfileConfig) -> Self {
        Self {
            post_processing: profile.post_processing,
            samples_config: profile.samples,
            dedupe_config: profile.dedupe,
            run_seed: None,
            engine_version: None,
            profile_meta: ProfileMeta {
                profile_name: profile.profile_name,
                version: profile.version,
            },
            run_id: None,
            input_hash: None,
        }
    }
}

// ---------- Added convenience builder methods for EngineOptions ----------
impl EngineOptions {
    pub fn with_run_seed(mut self, run_seed: Vec<u8>) -> Self {
        self.run_seed = Some(run_seed);
        self
    }

    pub fn with_run_id(mut self, run_id: String) -> Self {
        self.run_id = Some(run_id);
        self
    }

    pub fn with_input_hash(mut self, input_hash: String) -> Self {
        self.input_hash = Some(input_hash);
        self
    }

    pub fn with_engine_version(mut self, ver: String) -> Self {
        self.engine_version = Some(ver);
        self
    }
}
// -----------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub profile_name: String,
    pub display_name: Option<String>,
    pub version: String,
    pub description: Option<String>,
    pub path: Option<PathBuf>,
}

/// List available profiles by scanning candidate profile directories for `*.yaml`.
/// This is a best-effort helper used by interactive UI to show available profiles.
pub fn list_available_profiles() -> Vec<ProfileSummary> {
    let mut out = Vec::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();

    let candidate_dirs = vec![
        dirs::home_dir().map(|p| p.join(".cleansh").join("profiles")),
        dirs::config_dir().map(|p| p.join("cleansh").join("profiles")),
        Some(PathBuf::from("/etc/cleansh/profiles")),
        Some(PathBuf::from("./config")),
        Some(PathBuf::from("../config")),
    ];

    for maybe_dir in candidate_dirs.into_iter().flatten() {
        if let Ok(entries) = std::fs::read_dir(&maybe_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if path.extension().and_then(|s| s.to_str()) == Some("yaml") && seen_paths.insert(path.clone()) {
                    debug!("Found potential profile at: {}", path.display());
                    match fs::read_to_string(&path) {
                        Ok(s) => {
                            if let Ok(cfg) = serde_yml::from_str::<ProfileConfig>(&s) {
                                out.push(ProfileSummary {
                                    profile_name: cfg.profile_name,
                                    display_name: cfg.display_name,
                                    version: cfg.version,
                                    description: cfg.description,
                                    path: Some(path),
                                });
                            } else {
                                warn!("Failed to parse YAML for profile at: {}", path.display());
                            }
                        }
                        Err(e) => {
                            warn!("Failed to read profile file at '{}': {}", path.display(), e);
                        }
                    }
                }
            }
        } else {
            debug!("Candidate profile directory not found: {}", maybe_dir.display());
        }
    }
    out
}
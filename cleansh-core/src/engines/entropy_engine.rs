// cleansh-core/src/engines/entropy_engine.rs
//! A `SanitizationEngine` implementation that uses Shannon entropy and 
//! contextual analysis to identify and redact high-randomness secrets.
//! License: BUSL-1.1

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use strip_ansi_escapes::strip;
use sha2::{Digest, Sha256};
use hex;
use chrono::Utc;

use crate::config::{RedactionConfig, RedactionSummaryItem, RedactionRule};
use crate::redaction_match::{RedactionMatch, RedactionLog, ensure_match_hashes};
use crate::profiles::EngineOptions;
use crate::engine::SanitizationEngine;
use crate::sanitizers::compiler::{get_or_compile_rules, CompiledRules};

use cleansh_entropy::engine::EntropyEngine as LowLevelEntropyEngine;

/// Maps byte indices from a stripped string back to the original string,
/// preserving alignment when ANSI escape codes are removed.
#[derive(Debug)]
struct StrippedIndexMapper {
    map: Vec<usize>,
}

impl StrippedIndexMapper {
    fn new(original: &str) -> Self {
        let stripped_bytes = strip(original.as_bytes());
        let stripped_str = String::from_utf8_lossy(&stripped_bytes);

        let mut map: Vec<usize> = Vec::with_capacity(stripped_str.len() + 1);
        let mut orig_char_indices = original.char_indices();
        let mut current_orig_char = orig_char_indices.next();

        for stripped_char in stripped_str.chars() {
            while let Some((orig_index, orig_char)) = current_orig_char {
                if orig_char == stripped_char {
                    map.push(orig_index);
                    current_orig_char = orig_char_indices.next();
                    break;
                }
                current_orig_char = orig_char_indices.next();
            }
        }
        
        map.push(original.len());

        Self { map }
    }

    fn map_index(&self, stripped_index: usize) -> usize {
        let idx = stripped_index.min(self.map.len().saturating_sub(1));
        self.map[idx]
    }
}

/// A sanitization engine that detects secrets based on statistical entropy and context.
#[derive(Debug)]
pub struct EntropyEngine {
    config: RedactionConfig,
    options: EngineOptions,
    inner_engine: LowLevelEntropyEngine,
    compiled_rules: Arc<CompiledRules>,
}

impl EntropyEngine {
    /// Initializes the engine with the provided configuration.
    pub fn new(config: RedactionConfig) -> Result<Self> {
        Self::with_options(config, EngineOptions::default())
    }

    /// Initializes the engine with configuration and runtime options.
    ///
    /// It extracts the entropy threshold from `config.engines.entropy.threshold`.
    /// If not set, it defaults to `0.5`.
    pub fn with_options(config: RedactionConfig, options: EngineOptions) -> Result<Self> {
        let threshold = config.engines.entropy.threshold.unwrap_or(0.5);
        
        log::debug!("Initializing EntropyEngine with confidence threshold: {}", threshold);

        let inner_engine = LowLevelEntropyEngine::new(threshold);
        let compiled_rules = get_or_compile_rules(&config)?;

        Ok(Self {
            config,
            options,
            inner_engine,
            compiled_rules,
        })
    }

    fn create_redaction_match(
        &self,
        original_match_str: &str,
        start: u64,
        end: u64,
        confidence: f64,
        entropy: f64,
        stripped_input: &str,
        source_id: &str,
    ) -> RedactionMatch {
        let mut sample_hash = None;
        let mut match_context_hash = None;

        let needs_sample_hash = self.options.post_processing.as_ref().map_or(false, |pp| pp.replace_with_token) ||
            self.options.samples_config.is_some();
        let needs_context_hash = self.options.dedupe_config.as_ref().map_or(false, |dedupe| dedupe.use_hash);

        if needs_sample_hash || needs_context_hash {
            let mut hasher = Sha256::new();
            if needs_sample_hash {
                hasher.update(original_match_str.as_bytes());
                sample_hash = Some(hex::encode(hasher.finalize_reset()));
            }
            if needs_context_hash {
                let window = self.options.dedupe_config.as_ref().map(|d| d.window_bytes).unwrap_or(0);
                let ctx_start = (start as usize).saturating_sub(window);
                let ctx_end = std::cmp::min(stripped_input.len(), (end as usize).saturating_add(window));
                let ctx = &stripped_input[ctx_start..ctx_end];
                hasher.update(ctx.as_bytes());
                match_context_hash = Some(hex::encode(hasher.finalize()));
            }
        }

        let rule = RedactionRule {
            name: "high_entropy_secret".to_string(),
            description: Some(format!("Dynamic Entropy Detection (Confidence: {:.2}, Entropy: {:.2})", confidence, entropy)),
            pattern: None,
            replace_with: "[ENTROPY_REDACTED]".to_string(),
            pattern_type: "entropy".to_string(),
            version: "1.0.0".to_string(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            author: "CleanSH Entropy Engine".to_string(),
            multiline: false,
            dot_matches_new_line: false,
            opt_in: false,
            programmatic_validation: false,
            enabled: Some(true),
            severity: Some("high".to_string()),
            tags: None,
        };

        RedactionMatch {
            rule_name: rule.name.clone(),
            original_string: original_match_str.to_string(),
            sanitized_string: rule.replace_with.clone(),
            start,
            end,
            sample_hash,
            match_context_hash,
            timestamp: Some(Utc::now().to_rfc3339()),
            rule,
            source_id: source_id.to_string(),
            line_number: None,
        }
    }

    fn find_matches_internal(&self, content: &str, source_id: &str) -> Vec<RedactionMatch> {
        let stripped_bytes = strip(content.as_bytes());
        let stripped_input = String::from_utf8_lossy(&stripped_bytes);

        let entropy_matches = self.inner_engine.scan(stripped_input.as_bytes());

        let mut red_matches = Vec::new();

        for em in entropy_matches {
            let match_str = &stripped_input[em.start..em.end];
            
            let rm = self.create_redaction_match(
                match_str,
                em.start as u64,
                em.end as u64,
                em.confidence,
                em.entropy,
                &stripped_input,
                source_id
            );
            red_matches.push(rm);
        }

        red_matches
    }
}

impl SanitizationEngine for EntropyEngine {
    fn sanitize(
        &self,
        content: &str,
        source_id: &str,
        run_id: &str,
        input_hash: &str,
        user_id: &str,
        reason: &str,
        outcome: &str,
        mut audit_log: Option<&mut crate::audit_log::AuditLog>,
    ) -> Result<(String, Vec<RedactionSummaryItem>)> {
        let matches = self.find_matches_internal(content, source_id);
        
        let mapper = StrippedIndexMapper::new(content);
        let mut sanitized_content = String::with_capacity(content.len());
        let mut last_end = 0usize;

        let mut summary_map: HashMap<String, RedactionSummaryItem> = HashMap::new();

        let mut sorted_matches = matches;
        sorted_matches.sort_by_key(|m| m.start);

        for m in &sorted_matches {
            let original_start_byte = mapper.map_index(m.start as usize);
            let original_end_byte = mapper.map_index(m.end as usize);

            if original_end_byte <= last_end {
                continue;
            }

            let current_start = original_start_byte.max(last_end);
            sanitized_content.push_str(&content[last_end..current_start]);
            sanitized_content.push_str(&m.sanitized_string);
            last_end = original_end_byte;

            if let Some(log) = audit_log.as_mut() {
                let rlog = RedactionLog {
                    timestamp: m.timestamp.clone().unwrap_or_default(),
                    run_id: run_id.to_string(),
                    file_path: source_id.to_string(),
                    user_id: user_id.to_string(),
                    reason_for_redaction: reason.to_string(),
                    redaction_outcome: outcome.to_string(),
                    rule_name: m.rule_name.clone(),
                    input_hash: input_hash.to_string(),
                    match_hash: m.sample_hash.clone().unwrap_or_default(),
                    start: m.start,
                    end: m.end,
                };
                let _ = log.append(&rlog);
            }

            let entry = summary_map.entry(m.rule_name.clone()).or_insert_with(|| RedactionSummaryItem {
                rule_name: m.rule_name.clone(),
                occurrences: 0,
                original_texts: Vec::new(),
                sanitized_texts: Vec::new(),
            });
            entry.occurrences += 1;
            entry.original_texts.push(m.original_string.clone());
            entry.sanitized_texts.push(m.sanitized_string.clone());
        }

        sanitized_content.push_str(&content[last_end..]);

        let summary: Vec<RedactionSummaryItem> = summary_map.into_values().collect();
        Ok((sanitized_content, summary))
    }

    fn analyze_for_stats(&self, content: &str, source_id: &str) -> Result<Vec<RedactionSummaryItem>> {
        let matches = self.find_matches_internal(content, source_id);
        
        let mut summary_map: HashMap<String, RedactionSummaryItem> = HashMap::new();
        for m in matches {
            let entry = summary_map.entry(m.rule_name.clone()).or_insert_with(|| RedactionSummaryItem {
                rule_name: m.rule_name.clone(),
                occurrences: 0,
                original_texts: Vec::new(),
                sanitized_texts: Vec::new(),
            });
            entry.occurrences += 1;
            entry.original_texts.push(m.original_string);
            entry.sanitized_texts.push(m.sanitized_string);
        }
        
        Ok(summary_map.into_values().collect())
    }

    fn find_matches_for_ui(&self, content: &str, source_id: &str) -> Result<Vec<RedactionMatch>> {
        let mut matches = self.find_matches_internal(content, source_id);
        ensure_match_hashes(&mut matches);
        matches.sort_by_key(|m| m.start);
        Ok(matches)
    }

    fn compiled_rules(&self) -> &CompiledRules {
        &self.compiled_rules
    }

    fn get_rules(&self) -> &RedactionConfig {
        &self.config
    }

    fn get_options(&self) -> &EngineOptions {
        &self.options
    }
}
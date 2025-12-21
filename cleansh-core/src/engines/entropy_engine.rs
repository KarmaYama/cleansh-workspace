// cleansh-core/src/engines/entropy_engine.rs
//! A `SanitizationEngine` implementation utilizing Shannon entropy.
//! Features v0.2.0 Self-Healing Integration and Contiguous Match Merging.
//!
//! FIXED: Implemented 'Look-Ahead Stitcher' to prevent window fractures on long secrets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use anyhow::Result;
use strip_ansi_escapes::strip;
use sha2::{Digest, Sha256};
use hex;
use chrono::Utc;
use tokio::sync::mpsc;

use crate::config::{RedactionConfig, RedactionSummaryItem, RedactionRule};
use crate::redaction_match::{RedactionMatch, ensure_match_hashes};
use crate::profiles::EngineOptions;
use crate::engine::SanitizationEngine;
use crate::sanitizers::compiler::{get_or_compile_rules, CompiledRules};
use crate::remediation::fingerprint::SecretFingerprint;
use cleansh_entropy::engine::EntropyEngine as LowLevelEntropyEngine;

/// Improved Mapper: Handles ANSI escape offsets to prevent partial redaction.
#[derive(Debug)]
struct StrippedIndexMapper {
    map: Vec<usize>,
}

impl StrippedIndexMapper {
    fn new(original: &str) -> Self {
        let stripped_bytes = strip(original.as_bytes());
        let stripped_str = String::from_utf8_lossy(&stripped_bytes);
        
        let mut map: Vec<usize> = Vec::with_capacity(stripped_str.len() + 1);
        let mut orig_char_indices = original.char_indices().peekable();
        
        for stripped_char in stripped_str.chars() {
            while let Some(&(orig_index, orig_char)) = orig_char_indices.peek() {
                if orig_char == stripped_char {
                    map.push(orig_index);
                    let _ = orig_char_indices.next();
                    break;
                } else {
                    let _ = orig_char_indices.next();
                }
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

#[derive(Debug)]
pub struct EntropyEngine {
    config: RedactionConfig,
    options: EngineOptions,
    inner_engine: LowLevelEntropyEngine,
    compiled_rules: Arc<CompiledRules>,
    remediation_tx: Option<mpsc::Sender<RedactionMatch>>,
    fingerprint_cache: HashSet<String>,
}

impl EntropyEngine {
    pub fn new(config: RedactionConfig) -> Result<Self> {
        Self::with_options(config, EngineOptions::default())
    }

    pub fn with_options(config: RedactionConfig, options: EngineOptions) -> Result<Self> {
        let threshold = config.engines.entropy.threshold.unwrap_or(0.5);
        let window_size = config.engines.entropy.window_size.unwrap_or(24);
        let inner_engine = LowLevelEntropyEngine::new(threshold, window_size);
        let compiled_rules = get_or_compile_rules(&config)?;
        Ok(Self { 
            config, 
            options, 
            inner_engine, 
            compiled_rules, 
            remediation_tx: None, 
            fingerprint_cache: HashSet::new() 
        })
    }

    pub fn update_fingerprints(&mut self, fingerprints: Vec<SecretFingerprint>) {
        for fp in fingerprints { 
            self.fingerprint_cache.insert(fp.hash); 
        }
    }

    fn create_redaction_match(&self, original: &str, start: u64, end: u64, source_id: &str) -> RedactionMatch {
        let mut sample_hash = None;
        if self.options.post_processing.as_ref().map_or(false, |pp| pp.replace_with_token) {
            let mut hasher = Sha256::new();
            hasher.update(original.as_bytes());
            sample_hash = Some(hex::encode(hasher.finalize()));
        }
        let rule = RedactionRule {
            name: "high_entropy_secret".to_string(),
            replace_with: "[ENTROPY_REDACTED]".to_string(),
            pattern_type: "entropy".to_string(),
            ..Default::default()
        };
        RedactionMatch {
            rule_name: rule.name.clone(), 
            original_string: original.to_string(),
            sanitized_string: rule.replace_with.clone(), 
            start, 
            end, 
            sample_hash,
            match_context_hash: None, 
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
        if entropy_matches.is_empty() { return vec![]; }

        // --- MERGE LOGIC START ---
        let mut sorted_intervals = entropy_matches;
        sorted_intervals.sort_by(|a, b| a.start.cmp(&b.start));

        let mut merged_intervals = Vec::new();
        let mut current_start = sorted_intervals[0].start;
        let mut current_end = sorted_intervals[0].end;

        for m in sorted_intervals.into_iter().skip(1) {
            if m.start <= current_end {
                current_end = std::cmp::max(current_end, m.end);
            } else {
                merged_intervals.push((current_start, current_end));
                current_start = m.start;
                current_end = m.end;
            }
        }
        merged_intervals.push((current_start, current_end));
        // --- MERGE LOGIC END ---

        merged_intervals.into_iter().map(|(start, end)| {
            // Apply refined surgical extraction AND Look-Ahead Stitcher
            let (refined_start, refined_end) = self.extract_secret_core_indices(&stripped_input, start, end);
            
            let m = self.create_redaction_match(
                &stripped_input[refined_start..refined_end], 
                refined_start as u64, 
                refined_end as u64, 
                source_id
            );
            if let Some(tx) = &self.remediation_tx { 
                let _ = tx.try_send(m.clone()); 
            }
            m
        }).collect()
    }

    /// Heat-Seeker: Refines the match by anchoring to delimiters.
    /// NEW: Look-Ahead Stitcher to extend redaction beyond the initial window if characters remain.
    fn extract_secret_core_indices(&self, text: &str, raw_start: usize, raw_end: usize) -> (usize, usize) {
        let bytes = text.as_bytes();
        let len = bytes.len();
        let mut start = raw_start;
        let mut end = raw_end;

        // 1. Semantic Anchor: Snap to label delimiters (e.g. key=)
        let search_range = &bytes[start..end];
        if let Some(pos) = search_range.iter().rposition(|&b| b == b':' || b == b'=') {
            let potential_start = start + pos + 1;
            if potential_start < end {
                start = potential_start;
            }
        }

        // 2. Character-Class Trimming (Leading)
        while start < end && (
            bytes[start].is_ascii_whitespace() || 
            matches!(bytes[start], b'"' | b'\'' | b'[' | b'{' | b'<' | b'(' | b'-' | b'_')
        ) {
            start += 1;
        }

        // 3. LOOK-AHEAD STITCHER (The Fix for Partial Redaction)
        // If we reached the end of the window, peek forward. If the next characters are
        // alphanumeric/base64-safe, assume the window fractured a long secret and keep eating.
        while end < len {
            let b = bytes[end];
            // Stop ONLY if we hit a hard delimiter or whitespace.
            // If it's alphanumeric, underscore, or common secret chars (+, /, -), we extend.
            if b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b',' | b';' | b']' | b'}' | b')' | b'>') {
                break;
            }
            end += 1;
        }

        // 4. Tail Trimming (Safety Check)
        // Backtrack from the new end if we accidentally ate a trailing quote or punctuation.
        while (end - start) > 2 {
            let tail_byte = bytes[end - 1];
            if tail_byte.is_ascii_whitespace() 
                || matches!(tail_byte, b'.' | b',' | b'!' | b'?' | b']' | b'}' | b'>' | b')' | b'"' | b'\'' | b';') 
            {
                end -= 1;
            } else {
                break;
            }
        }

        (start, end)
    }
}

impl SanitizationEngine for EntropyEngine {
    fn sanitize(
        &self, 
        content: &str, 
        source_id: &str, 
        _run_id: &str, 
        _input_hash: &str, 
        _user_id: &str, 
        _reason: &str, 
        _outcome: &str, 
        _audit_log: Option<&mut crate::audit_log::AuditLog>
    ) -> Result<(String, Vec<RedactionSummaryItem>)> {
        let matches = self.find_matches_internal(content, source_id);
        let mapper = StrippedIndexMapper::new(content);
        let mut sanitized = String::with_capacity(content.len());
        let mut last_end = 0usize;
        let mut summary_map: HashMap<String, RedactionSummaryItem> = HashMap::new();
        let mut sorted = matches;
        
        sorted.sort_by_key(|m| m.start);

        for m in &sorted {
            let original_start = mapper.map_index(m.start as usize);
            let original_end = mapper.map_index(m.end as usize);
            
            if original_end <= last_end { continue; }
            
            sanitized.push_str(&content[last_end..original_start.max(last_end)]);
            sanitized.push_str(&m.sanitized_string);
            last_end = original_end;

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
        
        sanitized.push_str(&content[last_end..]);
        Ok((sanitized, summary_map.into_values().collect()))
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
        }
        Ok(summary_map.into_values().collect())
    }

    fn find_matches_for_ui(&self, content: &str, source_id: &str) -> Result<Vec<RedactionMatch>> {
        let mut matches = self.find_matches_internal(content, source_id);
        ensure_match_hashes(&mut matches);
        matches.sort_by_key(|m| m.start);
        Ok(matches)
    }

    fn get_heat_scores(&self, content: &str) -> Vec<f64> {
        let stripped_bytes = strip(content.as_bytes());
        let mut scores = Vec::with_capacity(content.len());
        
        for i in 0..stripped_bytes.len() {
            let start = i.saturating_sub(4);
            let end = std::cmp::min(stripped_bytes.len(), i + 5);
            scores.push(cleansh_entropy::entropy::calculate_shannon_entropy(&stripped_bytes[start..end]));
        }
        
        while scores.len() < content.len() { scores.push(0.0); }
        scores
    }

    fn compiled_rules(&self) -> &CompiledRules { &self.compiled_rules }
    fn get_rules(&self) -> &RedactionConfig { &self.config }
    fn get_options(&self) -> &EngineOptions { &self.options }
    fn set_remediation_tx(&mut self, tx: mpsc::Sender<RedactionMatch>) { self.remediation_tx = Some(tx); }
}
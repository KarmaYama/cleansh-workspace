//! The core entropy engine for CleanSH.
//!
//! Implements a sliding-window strategy for locator-based detection
//! and a heuristic-based extraction layer for precise redaction.
//!
//! This engine moves beyond static thresholds by identifying statistical outliers 
//! relative to a local baseline entropy.

extern crate alloc;
use alloc::vec::Vec;
use crate::scanner::{scan_token_against_context, AnomalyScannerConfig};
use crate::context::ContextScanner;
use crate::scoring::{calculate_confidence, ScoringWeights};

/// Represents a high-entropy anomaly found in text.
#[derive(Debug, Clone)]
pub struct EntropyMatch {
    pub start: usize,
    pub end: usize,
    pub confidence: f64,
    pub entropy: f64,
}

/// The main engine responsible for identifying anomalies by combining
/// statistical sliding-window entropy analysis with contextual keyword matching.
#[derive(Debug)]
pub struct EntropyEngine {
    scanner_config: AnomalyScannerConfig,
    context_scanner: ContextScanner,
    scoring_weights: ScoringWeights,
    confidence_threshold: f64,
    window_size: usize,
}

impl EntropyEngine {
    /// Initializes a new engine with specific detection parameters.
    pub fn new(threshold: f64, window_size: usize) -> Self {
        Self {
            scanner_config: AnomalyScannerConfig::default(),
            context_scanner: ContextScanner::new(),
            scoring_weights: ScoringWeights::default(),
            confidence_threshold: threshold,
            window_size,
        }
    }

    /// Scans a byte slice using a sliding-window approach and refines the boundaries.
    ///
    /// This multi-stage pipeline first locates "heat" and then surgically extracts 
    /// the secret core to avoid redacting surrounding natural language.
    pub fn scan(&self, text: &[u8]) -> Vec<EntropyMatch> {
        if text.len() < self.window_size {
            return Vec::new();
        }

        let mut raw_matches = Vec::new();
        let mut i = 0;

        // Pass 1: Statistical Locator (Sliding Window)
        while i <= text.len() - self.window_size {
            let window = &text[i..i + self.window_size];
            let anomaly = scan_token_against_context(window, text, i, &self.scanner_config);
            let has_context = self.context_scanner.scan_preceding_context(text, i, 48);

            let confidence = calculate_confidence(anomaly.z_score, has_context, &self.scoring_weights)
                .min(10.0);

            if confidence >= self.confidence_threshold {
                raw_matches.push(EntropyMatch {
                    start: i,
                    end: i + self.window_size,
                    confidence,
                    entropy: anomaly.token_entropy,
                });
                // Once we find heat, jump half a window to stay efficient
                i += self.window_size / 2; 
            } else {
                i += 1;
            }
        }

        // Pass 2: Consolidate overlapping windows into single blocks
        let consolidated = self.consolidate_matches(raw_matches);

        // Pass 3: Entropy Gradient Extraction (Surgical Trim)
        // Shrinks boundaries by walking back until entropy drops into natural language patterns.
        consolidated
            .into_iter()
            .map(|m| self.extract_secret_core(m, text))
            .filter(|m| (m.end - m.start) >= 6) // Final sanity check: secrets are rarely < 6 chars
            .collect()
    }

    /// Merges overlapping ranges from the sliding window into single contiguous redactions.
    fn consolidate_matches(&self, matches: Vec<EntropyMatch>) -> Vec<EntropyMatch> {
        if matches.is_empty() { return matches; }

        let mut merged = Vec::with_capacity(matches.len());
        let mut it = matches.into_iter();
        
        if let Some(mut current) = it.next() {
            for next in it {
                if next.start <= current.end {
                    current.end = next.end;
                    current.confidence = current.confidence.max(next.confidence);
                } else {
                    merged.push(current);
                    current = next;
                }
            }
            merged.push(current);
        }
        merged
    }

    /// Heat-Seeker: Refines the match by anchoring to delimiters and stripping entropy decay.
    ///
    /// This resolves the "signal-to-noise" crisis by finding the sharp drop-off 
    /// between random data and natural language (lowercase letters/spaces).
    fn extract_secret_core(&self, mut m: EntropyMatch, text: &[u8]) -> EntropyMatch {
        let mut start = m.start;
        let mut end = m.end;

        // 1. Semantic Anchor: Look for the split between label and value (e.g. key=)
        // We search for the last delimiter in the window to protect labels like 'auth_key='
        let search_range = &text[start..end];
        if let Some(pos) = search_range.iter().rposition(|&b| b == b':' || b == b'=') {
            let potential_start = start + pos + 1;
            if potential_start < end {
                start = potential_start;
            }
        }

        // 2. Character-Class Trimming (Leading)
        while start < end && (
            text[start].is_ascii_whitespace() || 
            matches!(text[start], b'"' | b'\'' | b'[' | b'{' | b'<' | b'(' | b'-' | b'_')
        ) {
            start += 1;
        }

        // 3. Statistical Decay Walk: Aggressive Tail Trimming
        // We walk backward from the end. Random secrets are usually mixed-case, 
        // hex, or symbols. Natural language is usually lowercase alphabetic.
        while (end - start) > 2 {
            let tail_byte = text[end - 1];
            
            // HARD STOP CONDITIONS for English noise:
            // - Stop if it's an underscore (common separator in 'extra_padding')
            // - Stop if it's lowercase (English words like 'padding' or 'ing')
            // - Stop if it's whitespace or sentence punctuation
            if tail_byte == b'_' 
                || tail_byte.is_ascii_lowercase() 
                || tail_byte.is_ascii_whitespace() 
                || matches!(tail_byte, b'.' | b',' | b'!' | b'?' | b']' | b'}' | b'>' | b')') 
            {
                end -= 1;
            } else {
                // If we hit a high-entropy char (digit, uppercase, or symbol), 
                // we have likely reached the end of the secret core.
                break;
            }
        }

        m.start = start;
        m.end = end;
        m
    }
}
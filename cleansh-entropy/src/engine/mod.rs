// cleansh-entropy/src/engine/mod.rs
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
/// statistical entropy analysis with contextual keyword matching.
#[derive(Debug)]
pub struct EntropyEngine {
    scanner_config: AnomalyScannerConfig,
    context_scanner: ContextScanner,
    scoring_weights: ScoringWeights,
    confidence_threshold: f64,
}

impl EntropyEngine {
    /// Initializes a new engine with a specific confidence threshold.
    pub fn new(threshold: f64) -> Self {
        Self {
            scanner_config: AnomalyScannerConfig::default(),
            context_scanner: ContextScanner::new(),
            scoring_weights: ScoringWeights::default(),
            confidence_threshold: threshold,
        }
    }

    /// Scans a byte slice for anomalies.
    pub fn scan(&self, text: &[u8]) -> Vec<EntropyMatch> {
        let mut matches = Vec::new();
        let mut start = 0;
        let mut in_token = false;

        for (i, &byte) in text.iter().enumerate() {
            // BLOB-SAFE TOKENIZATION: 
            // We include '+', '/', '.', and '=' to treat Base64 and JWTs as single units.
            let is_token_char = byte.is_ascii_alphanumeric() 
                || byte == b'_' || byte == b'-' 
                || byte == b'+' || byte == b'/' || byte == b'.' || byte == b'=';
            
            if is_token_char {
                if !in_token {
                    start = i;
                    in_token = true;
                }
            } else if in_token {
                self.process_token(text, start, i, &mut matches);
                in_token = false;
            }
        }

        // Handle last token if text doesn't end in a delimiter
        if in_token {
            self.process_token(text, start, text.len(), &mut matches);
        }

        matches
    }

    fn process_token(&self, text: &[u8], start: usize, end: usize, matches: &mut Vec<EntropyMatch>) {
        let token = &text[start..end];
        
        // Secrets shorter than 8 characters are excluded due to insufficient statistical significance.
        if token.len() < 8 { return; }

        // Statistical Outlier Pass (Leave-One-Out)
        let anomaly = scan_token_against_context(token, text, start, &self.scanner_config);
        
        // Early exit: ignore tokens that don't deviate from the local baseline.
        if anomaly.z_score < 1.0 { return; }

        // Contextual Boost Pass
        let has_context = self.context_scanner.scan_preceding_context(text, start, 48);
        
        // Calculate and clamp confidence to 0.0 - 10.0 range for ranking.
        let confidence = calculate_confidence(anomaly.z_score, has_context, &self.scoring_weights)
            .min(10.0);

        if confidence >= self.confidence_threshold {
            matches.push(EntropyMatch {
                start,
                end,
                confidence,
                entropy: anomaly.token_entropy,
            });
        }
    }
}
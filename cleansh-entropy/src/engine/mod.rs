extern crate alloc;
use alloc::vec::Vec;
use crate::scanner::{scan_token_against_context, AnomalyScannerConfig};
use crate::context::ContextScanner;
use crate::scoring::{calculate_confidence, ScoringWeights};

#[derive(Debug, Clone)]
pub struct EntropyMatch {
    pub start: usize,
    pub end: usize,
    pub confidence: f64,
    pub entropy: f64,
}

#[derive(Debug)]
pub struct EntropyEngine {
    scanner_config: AnomalyScannerConfig,
    context_scanner: ContextScanner,
    scoring_weights: ScoringWeights,
    confidence_threshold: f64,
}

impl EntropyEngine {
    pub fn new(threshold: f64) -> Self {
        Self {
            scanner_config: AnomalyScannerConfig::default(),
            context_scanner: ContextScanner::new(),
            scoring_weights: ScoringWeights::default(),
            confidence_threshold: threshold,
        }
    }

    pub fn scan(&self, text: &[u8]) -> Vec<EntropyMatch> {
        let mut matches = Vec::new();
        let mut start = 0;
        let mut in_token = false;

        for (i, &byte) in text.iter().enumerate() {
            let is_alphanum = byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-';
            
            if is_alphanum {
                if !in_token {
                    start = i;
                    in_token = true;
                }
            } else if in_token {
                self.process_token(text, start, i, &mut matches);
                in_token = false;
            }
        }
        if in_token {
            self.process_token(text, start, text.len(), &mut matches);
        }

        matches
    }

    fn process_token(&self, text: &[u8], start: usize, end: usize, matches: &mut Vec<EntropyMatch>) {
        let token = &text[start..end];
        
        // Minimum length check to filter out common short words
        if token.len() < 8 { return; }

        // FIX: Now passing 'start' as the offset to the scanner
        let anomaly = scan_token_against_context(token, text, start, &self.scanner_config);
        
        if anomaly.z_score < 1.0 { return; }

        let has_context = self.context_scanner.scan_preceding_context(text, start, 32);
        let confidence = calculate_confidence(anomaly.z_score, has_context, &self.scoring_weights);

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
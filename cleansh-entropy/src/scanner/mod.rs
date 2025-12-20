// cleansh-entropy/src/scanner/mod.rs
extern crate alloc;
use crate::entropy::calculate_shannon_entropy;
use crate::statistics::{compute_stats, EntropyStats};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct AnomalyScannerConfig {
    pub z_score_threshold: f64,
    pub window_chunk_size: usize, 
}

impl Default for AnomalyScannerConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            window_chunk_size: 32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub token_entropy: f64,
    pub baseline_stats: EntropyStats,
    pub z_score: f64,
}

/// A high-level scanner that iterates over a string to find statistical anomalies.
/// Now uses manual index tracking to avoid the "repeating token" find() bug.
pub struct Scanner<'a> {
    input: &'a str,
    remaining: &'a str,
    byte_offset: usize,
    config: AnomalyScannerConfig,
}

#[derive(Debug, Clone)]
pub struct ScanResult<'a> {
    pub token: &'a str,
    pub start: usize,
    pub end: usize,
    pub is_anomaly: bool,
    pub z_score: f64,
}

impl<'a> Scanner<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            remaining: input,
            byte_offset: 0,
            config: AnomalyScannerConfig::default(),
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = ScanResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // 1. Skip leading whitespace
        let trimmed_start = self.remaining.trim_start_matches(|c: char| c.is_whitespace());
        let leading_whitespace_len = self.remaining.len() - trimmed_start.len();
        self.byte_offset += leading_whitespace_len;
        self.remaining = trimmed_start;

        if self.remaining.is_empty() { return None; }

        // 2. Extract the next token
        let token_str = self.remaining.split_whitespace().next()?;
        let start = self.byte_offset;
        let end = start + token_str.len();

        // 3. Update state for next call
        self.byte_offset = end;
        self.remaining = &self.remaining[token_str.len()..];

        // 4. Perform the scan
        let result = scan_token_against_context(
            token_str.as_bytes(),
            self.input.as_bytes(),
            start,
            &self.config
        );

        Some(ScanResult {
            token: token_str,
            start,
            end,
            is_anomaly: result.is_anomaly,
            z_score: result.z_score,
        })
    }
}

pub fn scan_token_against_context(
    token: &[u8],
    context: &[u8],
    token_offset: usize,
    config: &AnomalyScannerConfig,
) -> AnomalyResult {
    let token_entropy = calculate_shannon_entropy(token);
    let token_len = token.len();
    let token_end = token_offset + token_len;
    
    let mut context_entropies = Vec::with_capacity(128); 
    let step = config.window_chunk_size.max(8);

    for (i, chunk) in context.chunks(step).enumerate() {
        let chunk_start = i * step;
        let chunk_end = chunk_start + chunk.len();

        // Strict Leave-One-Out: Skip chunks that overlap the candidate
        if chunk_start < token_end && chunk_end > token_offset {
            continue;
        }

        if context_entropies.len() >= 128 { break; }
        context_entropies.push(calculate_shannon_entropy(chunk));
    }

    if context_entropies.is_empty() {
        return AnomalyResult {
            is_anomaly: false,
            token_entropy,
            baseline_stats: EntropyStats { mean: 0.0, std_dev: 0.0, sample_count: 0 },
            z_score: 0.0,
        };
    }

    let stats = compute_stats(&context_entropies);

    let z_score = if stats.std_dev > 0.0 {
        (token_entropy - stats.mean) / stats.std_dev
    } else {
        if token_entropy > stats.mean { 100.0 } else { 0.0 }
    };

    AnomalyResult {
        is_anomaly: z_score > config.z_score_threshold,
        token_entropy,
        baseline_stats: stats,
        z_score,
    }
}
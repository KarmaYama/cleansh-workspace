// cleansh-entropy/src/scanner/mod.rs
use crate::entropy::calculate_shannon_entropy;
use crate::statistics::{compute_stats, EntropyStats};

/// Configuration for the dynamic entropy scanner.
#[derive(Debug, Clone)]
pub struct AnomalyScannerConfig {
    pub z_score_threshold: f64,
    pub window_chunk_size: usize, 
}

impl Default for AnomalyScannerConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            window_chunk_size: 0,
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

pub struct Scanner<'a> {
    input: &'a str,
    tokens: std::str::SplitWhitespace<'a>,
    config: AnomalyScannerConfig,
}

#[derive(Debug, Clone)]
pub struct ScanResult<'a> {
    pub token: &'a str,
    pub is_anomaly: bool,
    pub z_score: f64,
}

impl<'a> Scanner<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            tokens: input.split_whitespace(),
            config: AnomalyScannerConfig::default(),
        }
    }

    pub fn with_config(input: &'a str, config: AnomalyScannerConfig) -> Self {
        Self {
            input,
            tokens: input.split_whitespace(),
            config,
        }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = ScanResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let token_str = self.tokens.next()?;
        let result = scan_token_against_context(
            token_str.as_bytes(),
            self.input.as_bytes(),
            &self.config
        );

        Some(ScanResult {
            token: token_str,
            is_anomaly: result.is_anomaly,
            z_score: result.z_score,
        })
    }
}

pub fn scan_token_against_context(
    token: &[u8],
    context: &[u8],
    config: &AnomalyScannerConfig,
) -> AnomalyResult {
    let token_entropy = calculate_shannon_entropy(token);
    let token_len = token.len();
    
    if token_len == 0 || context.len() < token_len {
        return AnomalyResult {
            is_anomaly: false,
            token_entropy,
            baseline_stats: EntropyStats { mean: 0.0, std_dev: 0.0 },
            z_score: 0.0,
        };
    }

    let mut context_entropies = [0.0; 128]; 
    let mut sample_count = 0;
    let step = if config.window_chunk_size > 0 { config.window_chunk_size } else { token_len };
    let mut chunks = context.chunks(step);
    
    while let Some(chunk) = chunks.next() {
        if sample_count >= 128 { break; }
        if chunk.len() >= token_len / 2 {
             context_entropies[sample_count] = calculate_shannon_entropy(chunk);
             sample_count += 1;
        }
    }

    let stats = compute_stats(&context_entropies[0..sample_count]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec; // FIX: Required for no_std test macros
    use alloc::vec::Vec;

    #[test]
    fn test_anomaly_detection_natural_language() {
        let text = "This is a normal sentence with a secret token 8x9#bF2!kL*zZ inside it.";
        let mut config = AnomalyScannerConfig::default();
        config.z_score_threshold = 2.0; 
        let scanner = Scanner::with_config(text, config);
        let mut found_anomaly = false;
        for result in scanner {
            if result.token == "8x9#bF2!kL*zZ" {
                assert!(result.is_anomaly);
                found_anomaly = true;
            }
        }
        assert!(found_anomaly);
    }

    #[test]
    fn test_scanner_iterator_basic() {
        let text = "one two three";
        let scanner = Scanner::new(text);
        let tokens: Vec<&str> = scanner.map(|r| r.token).collect();
        assert_eq!(tokens, vec!["one", "two", "three"]);
    }
}